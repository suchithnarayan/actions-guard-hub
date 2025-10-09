#!/usr/bin/env python3
"""
AI Core Module with LangChain Integration

This module handles all AI/ML model interactions for security analysis using LangChain.
Supports multiple AI providers: Google Gemini, OpenAI, and easily extensible for others.

Features:
- LangChain-based AI model integration
- Multiple AI provider support (Gemini, OpenAI, etc.)
- Configurable cost calculation
- JSON validation and repair
- Unified interface for all models

Author: GitHub Actions Security Scanner Team
License: MIT
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from abc import ABC, abstractmethod
from pathlib import Path

# LangChain imports with graceful fallback
try:
    from langchain_google_genai import ChatGoogleGenerativeAI
    HAS_LANGCHAIN_GOOGLE = True
except ImportError:
    HAS_LANGCHAIN_GOOGLE = False

try:
    from langchain_openai import ChatOpenAI
    HAS_LANGCHAIN_OPENAI = True
except ImportError:
    HAS_LANGCHAIN_OPENAI = False

try:
    from langchain_anthropic import ChatAnthropic
    HAS_LANGCHAIN_ANTHROPIC = True
except ImportError:
    HAS_LANGCHAIN_ANTHROPIC = False

# Optional imports with graceful fallback
try:
    from json_repair import repair_json
    HAS_JSON_REPAIR = True
except ImportError:
    HAS_JSON_REPAIR = False

logger = logging.getLogger(__name__)


class AIModelInterface(ABC):
    """Abstract interface for AI models using LangChain."""
    
    @abstractmethod
    def analyze_security(self, prompt: str, action_files: Dict[str, str]) -> Dict[str, Any]:
        """Perform security analysis on action files."""
        pass
    
    @abstractmethod
    def validate_json(self, content: str) -> str:
        """Validate and repair JSON content."""
        pass
    
    @abstractmethod
    def calculate_cost(self, input_tokens: int, output_tokens: int, context_tokens: int = 0) -> float:
        """Calculate the cost of API usage."""
        pass
    
    @abstractmethod
    def get_model_info(self) -> Dict[str, str]:
        """Get model information."""
        pass


class CostCalculator:
    """Handles cost calculation for different AI models."""
    
    def __init__(self, cost_config_path: str = "ai_model_costs.json"):
        """Initialize cost calculator with configuration."""
        self.cost_config = self._load_cost_config(cost_config_path)
    
    def _load_cost_config(self, config_path: str) -> Dict:
        """Load cost configuration from JSON file."""
        try:
            if Path(config_path).exists():
                with open(config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"⚠️  Cost config file not found: {config_path}")
                return {}
        except Exception as e:
            logger.error(f"❌ Failed to load cost config: {e}")
            return {}
    
    def calculate_cost(self, provider: str, model: str, input_tokens: int, 
                      output_tokens: int, context_tokens: int = 0) -> float:
        """
        Calculate cost for a specific model using configuration-driven pricing.
        
        This method supports multiple pricing types defined in the configuration:
        - "simple": Fixed cost per million tokens
        - "tiered_by_total_tokens": Different rates based on total token count
        - "tiered_by_input_tokens": Different rates based on input token count
        - "tiered_by_output_tokens": Different rates based on output token count
        
        Args:
            provider: AI provider (gemini, openai, anthropic)
            model: Model name
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            context_tokens: Number of context tokens
            
        Returns:
            Total cost in USD
        """
        try:
            provider_config = self.cost_config.get(provider.lower(), {})
            model_config = provider_config.get("models", {}).get(model, {})
            
            if not model_config:
                logger.warning(f"⚠️  No cost config for {provider}/{model}, skipping cost calculation")
                return 0.0
            
            pricing_type = model_config.get("pricing_type", "simple")
            
            if pricing_type == "simple":
                return self._calculate_simple_cost(model_config, input_tokens, output_tokens, context_tokens)
            elif pricing_type == "tiered_by_total_tokens":
                return self._calculate_tiered_cost_by_total_tokens(model_config, input_tokens, output_tokens, context_tokens)
            elif pricing_type == "tiered_by_input_tokens":
                return self._calculate_tiered_cost_by_input_tokens(model_config, input_tokens, output_tokens, context_tokens)
            elif pricing_type == "tiered_by_output_tokens":
                return self._calculate_tiered_cost_by_output_tokens(model_config, input_tokens, output_tokens, context_tokens)
            else:
                logger.warning(f"⚠️  Unknown pricing type '{pricing_type}' for {provider}/{model}")
                return 0.0
            
        except Exception as e:
            logger.error(f"❌ Cost calculation failed: {e}")
            return 0.0
    
    def _calculate_simple_cost(self, model_config: Dict, input_tokens: int, 
                              output_tokens: int, context_tokens: int) -> float:
        """Calculate cost using simple fixed rates per million tokens."""
        input_cost_per_million = model_config.get("input_cost_per_million", 0)
        output_cost_per_million = model_config.get("output_cost_per_million", 0)
        context_cost_per_million = model_config.get("context_cost_per_million", 0)
        
        input_cost = (input_tokens / 1_000_000) * input_cost_per_million
        output_cost = (output_tokens / 1_000_000) * output_cost_per_million
        context_cost = (context_tokens / 1_000_000) * context_cost_per_million
        
        return input_cost + output_cost + context_cost
    
    def _calculate_tiered_cost_by_total_tokens(self, model_config: Dict, input_tokens: int, 
                                              output_tokens: int, context_tokens: int) -> float:
        """Calculate cost using tiers based on total token count."""
        total_tokens = input_tokens + output_tokens + context_tokens
        tiers = model_config.get("tiers", [])
        
        if not tiers:
            logger.warning("No tiers defined for tiered pricing model")
            return 0.0
        
        # Find the appropriate tier
        selected_tier = None
        for tier in tiers:
            threshold = tier.get("threshold", 0)
            condition = tier.get("condition", "<=")
            
            if condition == "<=" and total_tokens <= threshold:
                selected_tier = tier
                break
            elif condition == ">" and total_tokens > threshold:
                selected_tier = tier
                break
            elif condition == "<" and total_tokens < threshold:
                selected_tier = tier
                break
            elif condition == ">=" and total_tokens >= threshold:
                selected_tier = tier
                break
        
        if not selected_tier:
            # Use the last tier as fallback
            selected_tier = tiers[-1]
        
        input_cost_per_million = selected_tier.get("input_cost_per_million", 0)
        output_cost_per_million = selected_tier.get("output_cost_per_million", 0)
        context_cost_per_million = selected_tier.get("context_cost_per_million", 0)
        
        input_cost = (input_tokens / 1_000_000) * input_cost_per_million
        output_cost = (output_tokens / 1_000_000) * output_cost_per_million
        context_cost = (context_tokens / 1_000_000) * context_cost_per_million
        
        return input_cost + output_cost + context_cost
    
    def _calculate_tiered_cost_by_input_tokens(self, model_config: Dict, input_tokens: int, 
                                              output_tokens: int, context_tokens: int) -> float:
        """Calculate cost using tiers based on input token count."""
        # Similar logic but using input_tokens for tier selection
        return self._calculate_tiered_cost_by_token_type(model_config, input_tokens, output_tokens, context_tokens, "input")
    
    def _calculate_tiered_cost_by_output_tokens(self, model_config: Dict, input_tokens: int, 
                                               output_tokens: int, context_tokens: int) -> float:
        """Calculate cost using tiers based on output token count."""
        # Similar logic but using output_tokens for tier selection
        return self._calculate_tiered_cost_by_token_type(model_config, input_tokens, output_tokens, context_tokens, "output")
    
    def _calculate_tiered_cost_by_token_type(self, model_config: Dict, input_tokens: int, 
                                            output_tokens: int, context_tokens: int, token_type: str) -> float:
        """Helper method for token-type-specific tiered pricing."""
        token_count = input_tokens if token_type == "input" else output_tokens
        tiers = model_config.get("tiers", [])
        
        if not tiers:
            logger.warning(f"No tiers defined for tiered pricing model by {token_type} tokens")
            return 0.0
        
        # Find the appropriate tier
        selected_tier = None
        for tier in tiers:
            threshold = tier.get("threshold", 0)
            condition = tier.get("condition", "<=")
            
            if condition == "<=" and token_count <= threshold:
                selected_tier = tier
                break
            elif condition == ">" and token_count > threshold:
                selected_tier = tier
                break
            elif condition == "<" and token_count < threshold:
                selected_tier = tier
                break
            elif condition == ">=" and token_count >= threshold:
                selected_tier = tier
                break
        
        if not selected_tier:
            selected_tier = tiers[-1]
        
        input_cost_per_million = selected_tier.get("input_cost_per_million", 0)
        output_cost_per_million = selected_tier.get("output_cost_per_million", 0)
        context_cost_per_million = selected_tier.get("context_cost_per_million", 0)
        
        input_cost = (input_tokens / 1_000_000) * input_cost_per_million
        output_cost = (output_tokens / 1_000_000) * output_cost_per_million
        context_cost = (context_tokens / 1_000_000) * context_cost_per_million
        
        return input_cost + output_cost + context_cost


class LangChainGeminiModel(AIModelInterface):
    """Google Gemini AI model implementation using LangChain."""
    
    def __init__(self, model: str = "gemini-2.5-pro", api_key: Optional[str] = None, **kwargs):
        """
        Initialize Gemini model with LangChain.
        
        Args:
            model: Gemini model name
            api_key: Google API key (will use GOOGLE_API_KEY env var if not provided)
            **kwargs: Additional LangChain parameters
        """
        if not HAS_LANGCHAIN_GOOGLE:
            raise ImportError("langchain-google-genai is required for Gemini models. Install with: pip install langchain-google-genai")
        
        self.model_name = model
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        
        if not self.api_key:
            logger.warning("⚠️  Google API key not configured. Set GOOGLE_API_KEY environment variable.")
            raise ValueError("Google API key is required for Gemini models")
        
        # Initialize LangChain Gemini model
        try:
            self.llm = ChatGoogleGenerativeAI(
                model=model,
                temperature=kwargs.get("temperature", 0),
                max_tokens=kwargs.get("max_tokens", None),
                timeout=kwargs.get("timeout", 300),
                max_retries=kwargs.get("max_retries", 2),
                google_api_key=self.api_key
            )
            logger.info(f"✅ Initialized Gemini model: {model}")
        except Exception as e:
            logger.error(f"❌ Failed to initialize Gemini model: {e}")
            raise
        
        self.cost_calculator = CostCalculator()
    
    def analyze_security(self, prompt: str, action_files: Dict[str, str]) -> Dict[str, Any]:
        """
        Perform AI-powered security analysis using LangChain Gemini.
        
        Args:
            prompt: Security analysis prompt
            action_files: Dictionary of file paths to contents
            
        Returns:
            Dictionary with analysis results
        """
        result = {
            'success': False,
            'content': None,
            'tokens_used': 0,
            'cost': 0.0,
            'error': None
        }
        
        try:
            if not prompt:
                result['error'] = "Security prompt not provided"
                return result
            
            # Construct analysis prompt
            full_prompt = prompt + "\n\nHere are the GitHub Action files:\n"
            for filename, content in action_files.items():
                full_prompt += f"\n\n### File: {filename} ###\n{content}\n"
            
            logger.info(f"🤖 Analyzing with Gemini via LangChain ({len(action_files)} files)...")
            
            # Create messages for LangChain
            messages = [
                ("system", "You are a security expert analyzing GitHub Actions for vulnerabilities and malicious code."),
                ("human", full_prompt)
            ]
            
            # Invoke the model
            response = self.llm.invoke(messages)
            
            # Extract response content and metadata
            content = response.content
            usage_metadata = getattr(response, 'usage_metadata', {})
            
            input_tokens = usage_metadata.get('input_tokens', 0)
            output_tokens = usage_metadata.get('output_tokens', 0)
            total_tokens = usage_metadata.get('total_tokens', input_tokens + output_tokens)
            
            # Calculate cost
            cost = self.cost_calculator.calculate_cost("gemini", self.model_name, input_tokens, output_tokens, 0)
            
            result.update({
                'success': True,
                'content': content,
                'tokens_used': total_tokens,
                'cost': cost
            })
            
            logger.info(f"✅ Gemini analysis completed (tokens: {total_tokens}, cost: ${cost:.4f})")
            return result
            
        except Exception as e:
            logger.error(f"❌ Gemini analysis failed: {e}")
            result['error'] = str(e)
            return result
    
    def validate_json(self, content: str) -> str:
        """
        Use Gemini via LangChain to validate and fix JSON content.
        
        Args:
            content: Raw JSON content that may be malformed
            
        Returns:
            Repaired JSON content or original if repair fails
        """
        logger.info("🤖 Using Gemini via LangChain to validate and fix JSON format...")
        
        validation_prompt = """
        Check if the following content is valid JSON. If it is, return the exact same JSON.
        If it's not valid JSON, fix the formatting issues and return the corrected JSON.
        Make sure the output is properly formatted JSON with no additional text or explanations.
        Do not include ```json markers or any other formatting.
        Double check to make sure it's valid JSON format with no errors.

        Content to validate and fix:
        """
        
        try:
            messages = [
                ("system", "You are a JSON validation expert. Return only valid JSON without any additional formatting or explanations."),
                ("human", validation_prompt + "\n\n" + content)
            ]
            
            response = self.llm.invoke(messages)
            validated_content = response.content.strip()
            
            # Remove any markdown code block markers if present
            validated_content = validated_content.replace("```json", "").replace("```", "").strip()
            
            # Test if the repaired JSON is valid
            json.loads(validated_content)
            logger.debug("✅ LangChain JSON repair successful")
            return validated_content
            
        except json.JSONDecodeError:
            logger.warning("⚠️  LangChain returned invalid JSON for repair")
        except Exception as e:
            logger.warning(f"⚠️  Error during LangChain JSON repair: {str(e)}")
        
        # Return original content if repair fails
        return content
    
    def calculate_cost(self, input_tokens: int, output_tokens: int, context_tokens: int = 0) -> float:
        """Calculate the cost of Gemini API usage."""
        return self.cost_calculator.calculate_cost("gemini", self.model_name, input_tokens, output_tokens, context_tokens)
    
    def get_model_info(self) -> Dict[str, str]:
        """Get information about the current Gemini model."""
        return {
            "provider": "google",
            "model": self.model_name,
            "framework": "langchain"
        }


class LangChainOpenAIModel(AIModelInterface):
    """OpenAI model implementation using LangChain."""
    
    def __init__(self, model: str = "gpt-4o-mini", api_key: Optional[str] = None, **kwargs):
        """
        Initialize OpenAI model with LangChain.
        
        Args:
            model: OpenAI model name
            api_key: OpenAI API key (will use OPENAI_API_KEY env var if not provided)
            **kwargs: Additional LangChain parameters
        """
        if not HAS_LANGCHAIN_OPENAI:
            raise ImportError("langchain-openai is required for OpenAI models. Install with: pip install langchain-openai")
        
        self.model_name = model
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        
        if not self.api_key:
            logger.warning("⚠️  OpenAI API key not configured. Set OPENAI_API_KEY environment variable.")
            raise ValueError("OpenAI API key is required for OpenAI models")
        
        # Initialize LangChain OpenAI model
        try:
            self.llm = ChatOpenAI(
                model=model,
                temperature=kwargs.get("temperature", 0),
                max_tokens=kwargs.get("max_tokens", None),
                timeout=kwargs.get("timeout", 300),
                max_retries=kwargs.get("max_retries", 2),
                api_key=self.api_key,
                stream_usage=True  # Enable usage tracking
            )
            logger.info(f"✅ Initialized OpenAI model: {model}")
        except Exception as e:
            logger.error(f"❌ Failed to initialize OpenAI model: {e}")
            raise
        
        self.cost_calculator = CostCalculator()
    
    def analyze_security(self, prompt: str, action_files: Dict[str, str]) -> Dict[str, Any]:
        """
        Perform AI-powered security analysis using LangChain OpenAI.
        
        Args:
            prompt: Security analysis prompt
            action_files: Dictionary of file paths to contents
            
        Returns:
            Dictionary with analysis results
        """
        result = {
            'success': False,
            'content': None,
            'tokens_used': 0,
            'cost': 0.0,
            'error': None
        }
        
        try:
            if not prompt:
                result['error'] = "Security prompt not provided"
                return result
            
            # Construct analysis prompt
            full_prompt = prompt + "\n\nHere are the GitHub Action files:\n"
            for filename, content in action_files.items():
                full_prompt += f"\n\n### File: {filename} ###\n{content}\n"
            
            logger.info(f"🤖 Analyzing with OpenAI via LangChain ({len(action_files)} files)...")
            
            # Create messages for LangChain
            messages = [
                ("system", "You are a security expert analyzing GitHub Actions for vulnerabilities and malicious code."),
                ("human", full_prompt)
            ]
            
            # Invoke the model
            response = self.llm.invoke(messages)
            
            # Extract response content and metadata
            content = response.content
            usage_metadata = getattr(response, 'usage_metadata', {})
            
            input_tokens = usage_metadata.get('input_tokens', 0)
            output_tokens = usage_metadata.get('output_tokens', 0)
            total_tokens = usage_metadata.get('total_tokens', input_tokens + output_tokens)
            
            # Calculate cost
            cost = self.cost_calculator.calculate_cost("openai", self.model_name, input_tokens, output_tokens, 0)
            
            result.update({
                'success': True,
                'content': content,
                'tokens_used': total_tokens,
                'cost': cost
            })
            
            logger.info(f"✅ OpenAI analysis completed (tokens: {total_tokens}, cost: ${cost:.4f})")
            return result
            
        except Exception as e:
            logger.error(f"❌ OpenAI analysis failed: {e}")
            result['error'] = str(e)
            return result
    
    def validate_json(self, content: str) -> str:
        """
        Use OpenAI via LangChain to validate and fix JSON content.
        
        Args:
            content: Raw JSON content that may be malformed
            
        Returns:
            Repaired JSON content or original if repair fails
        """
        logger.info("🤖 Using OpenAI via LangChain to validate and fix JSON format...")
        
        validation_prompt = """
        Check if the following content is valid JSON. If it is, return the exact same JSON.
        If it's not valid JSON, fix the formatting issues and return the corrected JSON.
        Make sure the output is properly formatted JSON with no additional text or explanations.
        Do not include ```json markers or any other formatting.
        Double check to make sure it's valid JSON format with no errors.

        Content to validate and fix:
        """
        
        try:
            messages = [
                ("system", "You are a JSON validation expert. Return only valid JSON without any additional formatting or explanations."),
                ("human", validation_prompt + "\n\n" + content)
            ]
            
            response = self.llm.invoke(messages)
            validated_content = response.content.strip()
            
            # Remove any markdown code block markers if present
            validated_content = validated_content.replace("```json", "").replace("```", "").strip()
            
            # Test if the repaired JSON is valid
            json.loads(validated_content)
            logger.debug("✅ LangChain OpenAI JSON repair successful")
            return validated_content
            
        except json.JSONDecodeError:
            logger.warning("⚠️  LangChain OpenAI returned invalid JSON for repair")
        except Exception as e:
            logger.warning(f"⚠️  Error during LangChain OpenAI JSON repair: {str(e)}")
        
        # Return original content if repair fails
        return content
    
    def calculate_cost(self, input_tokens: int, output_tokens: int, context_tokens: int = 0) -> float:
        """Calculate the cost of OpenAI API usage."""
        return self.cost_calculator.calculate_cost("openai", self.model_name, input_tokens, output_tokens, context_tokens)
    
    def get_model_info(self) -> Dict[str, str]:
        """Get information about the current OpenAI model."""
        return {
            "provider": "openai",
            "model": self.model_name,
            "framework": "langchain"
        }


class AICore:
    """
    Main AI Core class that manages different AI models using LangChain.
    
    This class provides a unified interface for multiple AI providers and handles
    model selection, cost calculation, and JSON validation.
    """
    
    def __init__(self, model_type: str = "gemini", model_name: Optional[str] = None, **model_config):
        """
        Initialize AI Core with specified model.
        
        Args:
            model_type: Type of AI provider ("gemini", "openai", etc.)
            model_name: Specific model name (optional, uses defaults)
            **model_config: Model-specific configuration
        """
        self.model_type = model_type.lower()
        self.model_name = model_name
        self.model = self._create_model(self.model_type, model_name, **model_config)
        
        logger.debug(f"🤖 AI Core initialized with {self.model_type} model via LangChain")
    
    def _create_model(self, model_type: str, model_name: Optional[str], **config) -> AIModelInterface:
        """Create and return the specified AI model."""
        if model_type == "gemini":
            default_model = model_name or "gemini-2.5-flash"  # Changed to Flash for cost optimization
            return LangChainGeminiModel(model=default_model, **config)
        elif model_type == "openai":
            default_model = model_name or "gpt-4o-mini"
            return LangChainOpenAIModel(model=default_model, **config)
        else:
            available_models = ["gemini", "openai"]
            raise ValueError(f"Unsupported model type: {model_type}. Available: {available_models}")
    
    def analyze_security(self, prompt: str, action_files: Dict[str, str]) -> Dict[str, Any]:
        """
        Perform security analysis using the configured AI model.
        
        Args:
            prompt: Security analysis prompt
            action_files: Dictionary of file paths to contents
            
        Returns:
            Dictionary with analysis results
        """
        return self.model.analyze_security(prompt, action_files)
    
    def validate_and_repair_json(self, content: str) -> str:
        """
        Validate and repair JSON content using comprehensive repair strategies.
        
        This method implements multiple repair strategies:
        1. Try to parse JSON as-is
        2. Use json_repair library if available (local repair)
        3. Fallback to AI model for JSON repair
        4. Return original content if all methods fail
        
        Args:
            content: Raw content from AI analysis
            
        Returns:
            Validated/repaired JSON content
        """
        try:
            # First try to parse as-is
            json.loads(content)
            logger.debug("✅ JSON content is already valid")
            return content
        except json.JSONDecodeError as e:
            logger.warning(f"⚠️  Invalid JSON detected: {str(e)[:100]}...")
        
        # Try local repair first (faster and doesn't use API quota)
        repaired_content = self._validate_json_local(content)
        
        try:
            json.loads(repaired_content)
            logger.info("✅ JSON successfully repaired using local method")
            return repaired_content
        except json.JSONDecodeError:
            logger.warning("⚠️  Local JSON repair failed, trying AI method...")
        
        # Fallback to AI repair
        ai_repaired_content = self.model.validate_json(content)
        
        try:
            json.loads(ai_repaired_content)
            logger.info("✅ JSON successfully repaired using AI method")
            return ai_repaired_content
        except json.JSONDecodeError:
            logger.error("❌ All JSON repair methods failed, returning original content")
        
        # Final fallback: return original content (will be handled as raw text)
        return content
    
    def _validate_json_local(self, content: str) -> str:
        """
        Use json_repair library to fix JSON content locally.
        
        Args:
            content: Raw JSON content that may be malformed
            
        Returns:
            Repaired JSON content or original if repair fails
        """
        if not HAS_JSON_REPAIR:
            logger.debug("json_repair library not available, skipping local repair")
            return content
        
        logger.info("🔧 Using json_repair library to fix invalid JSON...")
        try:
            # Use repair_json with options for handling non-Latin characters
            repaired_json = repair_json(
                content,
                ensure_ascii=False,  # Preserve non-Latin characters
                stream_stable=True   # Better handling of potentially incomplete JSON
            )
            
            if not repaired_json:
                logger.warning("json_repair returned empty string")
                return content
            
            # Test if the repaired JSON is valid
            json.loads(repaired_json)
            logger.debug("✅ Local JSON repair successful")
            return repaired_json
            
        except Exception as e:
            logger.warning(f"⚠️  Error using json_repair: {str(e)}")
            return content
    
    def calculate_cost(self, input_tokens: int, output_tokens: int, context_tokens: int = 0) -> float:
        """Calculate the cost of AI model usage."""
        return self.model.calculate_cost(input_tokens, output_tokens, context_tokens)
    
    def get_model_info(self) -> Dict[str, str]:
        """Get information about the current AI model."""
        return self.model.get_model_info()
    
    @staticmethod
    def get_available_models() -> Dict[str, List[str]]:
        """Get list of available models by provider."""
        available = {}
        
        if HAS_LANGCHAIN_GOOGLE:
            available["gemini"] = ["gemini-2.5-pro", "gemini-2.5-flash"]
        
        if HAS_LANGCHAIN_OPENAI:
            available["openai"] = ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"]
        
        return available
    
    @staticmethod
    def get_required_env_vars() -> Dict[str, str]:
        """Get required environment variables for each provider."""
        return {
            "gemini": "GOOGLE_API_KEY",
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY"
        }


# Factory function for easy model creation
def create_ai_core(model_type: str = "gemini", model_name: Optional[str] = None, **config) -> AICore:
    """
    Factory function to create AI Core with specified model.
    
    Args:
        model_type: Type of AI provider to use
        model_name: Specific model name (optional)
        **config: Model-specific configuration
        
    Returns:
        Configured AICore instance
    
    Raises:
        ImportError: If required LangChain package is not installed
        ValueError: If API key is not configured
    """
    try:
        return AICore(model_type, model_name, **config)
    except ImportError as e:
        logger.error(f"❌ Missing required dependency: {e}")
        logger.info("💡 Install required packages:")
        if model_type == "gemini":
            logger.info("   pip install langchain-google-genai")
        elif model_type == "openai":
            logger.info("   pip install langchain-openai")
        raise
    except ValueError as e:
        logger.error(f"❌ Configuration error: {e}")
        env_vars = AICore.get_required_env_vars()
        if model_type in env_vars:
            logger.info(f"💡 Set environment variable: {env_vars[model_type]}")
        raise


def validate_model_setup(model_type: str) -> Tuple[bool, str]:
    """
    Validate that a model type is properly set up.
    
    Args:
        model_type: AI provider type to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        # Check if required packages are installed
        if model_type == "gemini" and not HAS_LANGCHAIN_GOOGLE:
            return False, "langchain-google-genai package not installed"
        elif model_type == "openai" and not HAS_LANGCHAIN_OPENAI:
            return False, "langchain-openai package not installed"
        
        # Check if required environment variables are set
        env_vars = AICore.get_required_env_vars()
        if model_type in env_vars:
            env_var = env_vars[model_type]
            if not os.getenv(env_var):
                return False, f"{env_var} environment variable not set"
        
        return True, "Model setup is valid"
        
    except Exception as e:
        return False, f"Validation error: {str(e)}"
