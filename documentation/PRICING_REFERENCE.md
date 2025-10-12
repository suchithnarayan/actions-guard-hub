# AI Model Pricing Reference

This document provides a quick reference for current AI model pricing configured in the system.

> **Note**: All prices are per million tokens unless otherwise specified. The system automatically calculates costs based on the configuration in `ai_model_costs.json`.

**Supported Pricing Types:**

1. **Simple Pricing** (fixed rates):
```json
{
  "provider": {
    "models": {
      "model-name": {
        "pricing_type": "simple",
        "input_cost_per_million": 1.25,
        "output_cost_per_million": 10.00,
        "context_cost_per_million": 0.31
      }
    }
  }
}
```

2. **Tiered Pricing** (rates change based on usage):
```json
{
  "gemini": {
    "models": {
      "gemini-2.5-pro": {
        "pricing_type": "tiered_by_total_tokens",
        "tiers": [
          {
            "threshold": 200000,
            "condition": "<=",
            "input_cost_per_million": 1.25,
            "output_cost_per_million": 10.00
          },
          {
            "threshold": 200000,
            "condition": ">",
            "input_cost_per_million": 2.50,
            "output_cost_per_million": 15.00
          }
        ]
      }
    }
  }
}
```

**Available Pricing Types:**
- `simple`: Fixed cost per million tokens
- `tiered_by_total_tokens`: Different rates based on total token count
- `tiered_by_input_tokens`: Different rates based on input token count  
- `tiered_by_output_tokens`: Different rates based on output token count

**Adding New Models:** Just update the JSON file - no code changes required!

> ⚠️ **Important**: Gemini pricing has increased significantly. For cost optimization:
> - Use **Gemini 2.5 Flash** for most use cases (much cheaper)
> - Monitor your usage costs carefully
> - Consider OpenAI GPT-4o-mini for very cost-sensitive applications


## 🤖 OpenAI Models

| Model | Input Cost | Output Cost | Use Case | Notes |
|-------|------------|-------------|----------|--------|
| **gpt-4o-mini** | $0.15 | $0.60 | **Recommended for most tasks** | Affordable, fast, lightweight |
| **gpt-3.5-turbo** | $0.50 | $1.50 | Simple tasks | Fast and inexpensive |
| **gpt-4o** | $2.50 | $10.00 | Flagship model | Latest multimodal capabilities |
| **o1-mini** | $3.00 | $12.00 | Reasoning tasks | Affordable reasoning model |
| **gpt-4-turbo** | $10.00 | $30.00 | High intelligence | Previous generation premium |
| **o1-preview** | $15.00 | $60.00 | Complex reasoning | Multi-step problem solving |
| **gpt-4** | $30.00 | $60.00 | Premium tasks | Original GPT-4 model |

## 🔮 Google Gemini Models

| Model | Pricing Type | Input Cost | Output Cost | Context Cost | Notes |
|-------|--------------|------------|-------------|--------------|--------|
| **gemini-2.5-flash** | Simple | $0.30 | $2.50 | $0.075 | **Recommended for cost optimization** |
| **gemini-2.5-flash-preview** | Simple | $0.30 | $2.50 | $0.075 | Preview version |
| **gemini-2.5-pro** | Tiered | $1.25-$2.50* | $10.00-$15.00* | $0.31-$0.625* | Tiered by total tokens (200k threshold) |

*Gemini Pro pricing tiers:
- ≤200k tokens: Lower rates
- >200k tokens: Higher rates

## 🧠 Anthropic Models

| Model | Input Cost | Output Cost | Use Case |
|-------|------------|-------------|----------|
| **claude-3-haiku** | $0.25 | $1.25 | Fast, affordable tasks |
| **claude-3-5-sonnet** | $3.00 | $15.00 | Advanced reasoning |

## 💰 Cost Comparison Examples

### Small Request (1,000 input + 500 output tokens)
| Provider/Model | Cost | Ranking |
|----------------|------|---------|
| openai/gpt-4o-mini | $0.000450 | 🥇 Most affordable |
| anthropic/claude-3-haiku | $0.000875 | 🥈 Second best |
| openai/gpt-3.5-turbo | $0.001250 | 🥉 Third best |
| gemini/gemini-2.5-flash | $0.001550 | Good value |

### Medium Request (10,000 input + 5,000 output tokens)
| Provider/Model | Cost | Ranking |
|----------------|------|---------|
| openai/gpt-4o-mini | $0.004500 | 🥇 Most affordable |
| anthropic/claude-3-haiku | $0.008750 | 🥈 Second best |
| openai/gpt-3.5-turbo | $0.012500 | 🥉 Third best |
| gemini/gemini-2.5-flash | $0.015500 | Good value |

### Large Request (50,000 input + 25,000 output tokens)
| Provider/Model | Cost | Ranking |
|----------------|------|---------|
| openai/gpt-4o-mini | $0.022500 | 🥇 Most affordable |
| anthropic/claude-3-haiku | $0.043750 | 🥈 Second best |
| openai/gpt-3.5-turbo | $0.062500 | 🥉 Third best |
| gemini/gemini-2.5-flash | $0.077500 | Good value |

## 🔧 Configuration-Driven System

### Key Benefits
- ✅ **Zero code changes** needed for pricing updates
- ✅ **Automatic cost calculation** based on JSON configuration
- ✅ **Multiple pricing models** supported (simple, tiered)
- ✅ **Easy model addition** through configuration
- ✅ **Flexible tier conditions** (<=, >, <, >=)

### Adding New Models
To add a new model, simply update `ai_model_costs.json`:

```json
{
  "new_provider": {
    "models": {
      "new-model": {
        "pricing_type": "simple",
        "input_cost_per_million": 1.00,
        "output_cost_per_million": 2.00,
        "notes": "Description of the model"
      }
    }
  }
}
```

### Supported Pricing Types
1. **Simple**: Fixed cost per million tokens
2. **Tiered by Total Tokens**: Different rates based on total token count
3. **Tiered by Input Tokens**: Different rates based on input token count
4. **Tiered by Output Tokens**: Different rates based on output token count

## 📊 Usage Recommendations

### For Cost-Sensitive Applications
1. **OpenAI GPT-4o-mini** - Best overall value
2. **Anthropic Claude-3-haiku** - Good balance of cost and capability
3. **OpenAI GPT-3.5-turbo** - Reliable and affordable

### For High-Quality Analysis
1. **OpenAI GPT-4o** - Latest flagship model
2. **Gemini 2.5 Pro** - Advanced capabilities with tiered pricing
3. **OpenAI o1-mini** - Reasoning capabilities at reasonable cost

### For Complex Reasoning Tasks
1. **OpenAI o1-preview** - Best reasoning capabilities
2. **OpenAI o1-mini** - Affordable reasoning model
3. **Anthropic Claude-3-5-sonnet** - Advanced reasoning

## 🔄 Keeping Pricing Updated

The pricing in this document reflects the configuration in `ai_model_costs.json`. To update pricing:

1. Edit `ai_model_costs.json` with new rates
2. No code changes required
3. System automatically uses new pricing
4. Update this reference document if needed

---

**Last Updated**: January 2025  
**Configuration File**: `ai_model_costs.json`  
**System**: Configuration-driven cost calculation
