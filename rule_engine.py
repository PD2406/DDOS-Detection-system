"""
Rule-based detection engine
"""
import yaml
import logging
from typing import Dict, List, Any, Callable
from datetime import datetime

logger = logging.getLogger(__name__)

class Rule:
    def __init__(self, name: str, condition: Callable, weight: float = 0.5, 
                 message: str = "", description: str = ""):
        self.name = name
        self.condition = condition
        self.weight = weight
        self.message = message
        self.description = description
        self.last_triggered = None
    
    def evaluate(self, data: Dict) -> bool:
        """Evaluate rule against data"""
        try:
            result = self.condition(data)
            if result:
                self.last_triggered = datetime.now()
            return result
        except Exception as e:
            logger.error(f"Error evaluating rule {self.name}: {e}")
            return False
    
    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "weight": self.weight,
            "message": self.message,
            "description": self.description,
            "last_triggered": self.last_triggered.isoformat() if self.last_triggered else None
        }

class RuleEngine:
    def __init__(self, rules_file: str = None):
        self.rules: List[Rule] = []
        self.triggered_rules: List[Dict] = []
        
        # Default rules
        self._create_default_rules()
        
        if rules_file:
            self.load_rules_from_file(rules_file)
    
    def _create_default_rules(self):
        """Create default DDoS detection rules"""
        default_rules = [
            Rule(
                name="high_request_rate",
                condition=lambda data: data.get('request_rate', 0) > 1000,
                weight=0.4,
                message="Request rate exceeds 1000 req/sec",
                description="Detects unusually high request rates"
            ),
            Rule(
                name="high_packet_rate",
                condition=lambda data: data.get('flow_packets_per_sec', 0) > 5000,
                weight=0.3,
                message="Packet rate exceeds 5000 pkt/sec",
                description="Detects high packet transmission rates"
            ),
            Rule(
                name="many_source_ips",
                condition=lambda data: data.get('unique_ips', 0) > 100,
                weight=0.3,
                message="More than 100 unique source IPs",
                description="Detects traffic from many different sources"
            ),
            Rule(
                name="short_flow_duration",
                condition=lambda data: data.get('flow_duration', 1000) < 100,
                weight=0.2,
                message="Flow duration less than 100ms",
                description="Detects very short network flows"
            ),
            Rule(
                name="udp_flood_pattern",
                condition=lambda data: (
                    data.get('protocol', '').upper() == 'UDP' and
                    data.get('request_rate', 0) > 500 and
                    data.get('avg_packet_size', 0) < 100
                ),
                weight=0.5,
                message="UDP flood pattern detected",
                description="Detects UDP flood attacks with small packets"
            ),
            Rule(
                name="syn_flood_pattern",
                condition=lambda data: (
                    data.get('protocol', '').upper() == 'TCP' and
                    data.get('syn_flag_count', 0) > data.get('ack_flag_count', 0) * 10
                ),
                weight=0.4,
                message="SYN flood pattern detected",
                description="Detects SYN flood attacks"
            )
        ]
        
        self.rules.extend(default_rules)
    
    def load_rules_from_file(self, filepath: str):
        """Load rules from YAML file"""
        try:
            with open(filepath, 'r') as f:
                rules_config = yaml.safe_load(f)
            
            for rule_config in rules_config.get('rules', []):
                # Convert string condition to lambda
                condition_str = rule_config.get('condition', '')
                condition = self._create_condition_from_string(condition_str)
                
                rule = Rule(
                    name=rule_config.get('name', ''),
                    condition=condition,
                    weight=rule_config.get('weight', 0.5),
                    message=rule_config.get('message', ''),
                    description=rule_config.get('description', '')
                )
                
                self.rules.append(rule)
            
            logger.info(f"Loaded {len(rules_config.get('rules', []))} rules from {filepath}")
            
        except Exception as e:
            logger.error(f"Error loading rules from {filepath}: {e}")
    
    def _create_condition_from_string(self, condition_str: str) -> Callable:
        """Create lambda function from condition string"""
        # Simple implementation - can be extended
        if '>' in condition_str:
            parts = condition_str.split('>')
            field = parts[0].strip()
            value = float(parts[1].strip())
            return lambda data: data.get(field, 0) > value
        elif '<' in condition_str:
            parts = condition_str.split('<')
            field = parts[0].strip()
            value = float(parts[1].strip())
            return lambda data: data.get(field, 0) < value
        elif '==' in condition_str:
            parts = condition_str.split('==')
            field = parts[0].strip()
            value = parts[1].strip().strip('"').strip("'")
            return lambda data: str(data.get(field, '')).upper() == value.upper()
        else:
            # Default condition (always false)
            return lambda data: False
    
    def evaluate_all(self, data: Dict) -> Dict[str, Any]:
        """Evaluate all rules against data"""
        triggered = []
        total_weight = 0.0
        
        for rule in self.rules:
            if rule.evaluate(data):
                triggered.append(rule.to_dict())
                total_weight += rule.weight
        
        # Calculate confidence
        confidence = min(total_weight, 1.0)
        is_attack = confidence > 0.7
        
        # Store triggered rules
        self.triggered_rules.append({
            "timestamp": datetime.now(),
            "data": {k: v for k, v in data.items() if k not in ['source_ips']},
            "triggered_rules": triggered,
            "confidence": confidence,
            "is_attack": is_attack
        })
        
        # Keep only recent history
        if len(self.triggered_rules) > 1000:
            self.triggered_rules = self.triggered_rules[-1000:]
        
        return {
            "is_attack": is_attack,
            "confidence": confidence,
            "triggered_rules": triggered,
            "total_rules": len(self.rules),
            "triggered_count": len(triggered)
        }
    
    def add_rule(self, rule: Rule):
        """Add a new rule"""
        self.rules.append(rule)
    
    def remove_rule(self, rule_name: str):
        """Remove a rule by name"""
        self.rules = [r for r in self.rules if r.name != rule_name]
    
    def get_rules(self) -> List[Dict]:
        """Get all rules as dictionaries"""
        return [rule.to_dict() for rule in self.rules]
    
    def get_stats(self) -> Dict:
        """Get rule engine statistics"""
        total_triggers = sum(len(item['triggered_rules']) for item in self.triggered_rules)
        
        return {
            "total_rules": len(self.rules),
            "active_rules": len([r for r in self.rules if r.last_triggered]),
            "total_evaluations": len(self.triggered_rules),
            "total_triggers": total_triggers,
            "recent_triggers": sum(len(item['triggered_rules']) for item in self.triggered_rules[-100:])
        }

# Global rule engine instance
rule_engine = RuleEngine()