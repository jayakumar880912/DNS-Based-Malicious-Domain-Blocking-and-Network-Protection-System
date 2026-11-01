"""
AegisDNS - Digital Twin & Policy Simulation Models
Defines models for Virtual Policies, Attack Scenarios, Simulation Runs, and Per-Domain Evaluation Items.
"""

from datetime import datetime, timezone
import json
from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class VirtualPolicy(db.Model):
    """
    Virtual DNS Security Policy.
    Allows administrators to configure sandboxed DNS protection rules without affecting live traffic.
    """
    __tablename__ = 'virtual_policies'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(150), nullable=False, unique=True, index=True)
    description = db.Column(db.Text, nullable=True)
    
    # Heuristic & Threshold Controls
    entropy_threshold = db.Column(db.Float, nullable=False, default=3.90)  # Shannon Entropy cutoff
    blocked_tlds_json = db.Column(db.Text, nullable=True)                  # List of high-risk TLDs
    blocked_categories_json = db.Column(db.Text, nullable=True)            # Phishing, C2, Malware, etc.
    dga_protection_mode = db.Column(db.String(50), nullable=False, default='Balanced') # Aggressive, Balanced, Conservative, Off
    ai_heuristic_weight = db.Column(db.Float, nullable=False, default=1.0) # Multiplier for lexical & typosquatting score
    min_confidence_score = db.Column(db.Integer, nullable=False, default=80)
    
    # Enforcement Actions in Simulation
    action_malicious = db.Column(db.String(50), nullable=False, default='SINKHOLE_0_0_0_0') # SINKHOLE_0_0_0_0, NXDOMAIN, REFUSED
    action_suspicious = db.Column(db.String(50), nullable=False, default='CHALLENGE_FLAG')  # BLOCK_SINKHOLE, CHALLENGE_FLAG, ALLOW_WITH_LOG
    
    # Policy Exceptions (Custom Rules)
    custom_whitelist_json = db.Column(db.Text, nullable=True) # Domain strings to always allow
    custom_blacklist_json = db.Column(db.Text, nullable=True) # Domain strings to always block
    
    is_baseline = db.Column(db.Boolean, default=False, nullable=False) # Represents live policy equivalent
    created_by = db.Column(db.String(100), default='SecOps Administrator')
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)
    updated_at = db.Column(db.DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    @property
    def blocked_tlds(self):
        if not self.blocked_tlds_json:
            return ['top', 'xyz', 'cc', 'ru', 'biz', 'online', 'loan', 'work', 'vip']
        try:
            return json.loads(self.blocked_tlds_json)
        except Exception:
            return [t.strip() for t in self.blocked_tlds_json.split(',') if t.strip()]

    @blocked_tlds.setter
    def blocked_tlds(self, value):
        if isinstance(value, list):
            self.blocked_tlds_json = json.dumps(value)
        elif isinstance(value, str):
            self.blocked_tlds_json = json.dumps([t.strip().lstrip('.') for t in value.split(',') if t.strip()])
        else:
            self.blocked_tlds_json = json.dumps([])

    @property
    def blocked_categories(self):
        if not self.blocked_categories_json:
            return ['Phishing', 'Malware C2', 'Ransomware Dropper', 'Cryptomining', 'DGA Anomaly']
        try:
            return json.loads(self.blocked_categories_json)
        except Exception:
            return [c.strip() for c in self.blocked_categories_json.split(',') if c.strip()]

    @blocked_categories.setter
    def blocked_categories(self, value):
        if isinstance(value, list):
            self.blocked_categories_json = json.dumps(value)
        else:
            self.blocked_categories_json = json.dumps([])

    @property
    def custom_whitelist(self):
        if not self.custom_whitelist_json:
            return []
        try:
            return json.loads(self.custom_whitelist_json)
        except Exception:
            return [d.strip() for d in self.custom_whitelist_json.split(',') if d.strip()]

    @custom_whitelist.setter
    def custom_whitelist(self, value):
        if isinstance(value, list):
            self.custom_whitelist_json = json.dumps(value)
        else:
            self.custom_whitelist_json = json.dumps([])

    @property
    def custom_blacklist(self):
        if not self.custom_blacklist_json:
            return []
        try:
            return json.loads(self.custom_blacklist_json)
        except Exception:
            return [d.strip() for d in self.custom_blacklist_json.split(',') if d.strip()]

    @custom_blacklist.setter
    def custom_blacklist(self, value):
        if isinstance(value, list):
            self.custom_blacklist_json = json.dumps(value)
        else:
            self.custom_blacklist_json = json.dumps([])

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description or '',
            'entropyThreshold': self.entropy_threshold,
            'blockedTlds': self.blocked_tlds,
            'blockedCategories': self.blocked_categories,
            'dgaProtectionMode': self.dga_protection_mode,
            'aiHeuristicWeight': self.ai_heuristic_weight,
            'minConfidenceScore': self.min_confidence_score,
            'actionMalicious': self.action_malicious,
            'actionSuspicious': self.action_suspicious,
            'customWhitelist': self.custom_whitelist,
            'customBlacklist': self.custom_blacklist,
            'isBaseline': self.is_baseline,
            'createdBy': self.created_by,
            'createdAt': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'updatedAt': self.updated_at.strftime('%Y-%m-%d %H:%M:%S')
        }


class SimulationScenario(db.Model):
    """
    Predefined or user-defined DNS attack & traffic scenario datasets.
    Contains labeled domain queries (ground truth) to measure policy precision and recall.
    """
    __tablename__ = 'simulation_scenarios'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scenario_key = db.Column(db.String(80), nullable=False, unique=True, index=True)
    name = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(100), nullable=False) # Phishing Surge, DGA Botnet, Ransomware, Mixed
    description = db.Column(db.Text, nullable=False)
    difficulty = db.Column(db.String(30), nullable=False, default='Advanced') # Normal, High, Advanced
    domain_count = db.Column(db.Integer, nullable=False, default=0)
    dataset_json = db.Column(db.Text, nullable=False) # JSON array of {domain, groundTruth, category, expectedVerdict, iocDetails}
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)

    @property
    def dataset(self):
        if not self.dataset_json:
            return []
        try:
            return json.loads(self.dataset_json)
        except Exception:
            return []

    @dataset.setter
    def dataset(self, value):
        if isinstance(value, list):
            self.dataset_json = json.dumps(value)
            self.domain_count = len(value)
        else:
            self.dataset_json = json.dumps([])
            self.domain_count = 0

    def to_dict(self, include_dataset=False):
        data = {
            'id': self.id,
            'scenarioKey': self.scenario_key,
            'name': self.name,
            'category': self.category,
            'description': self.description,
            'difficulty': self.difficulty,
            'domainCount': self.domain_count,
            'createdAt': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        if include_dataset:
            data['dataset'] = self.dataset
        return data


class SimulationRun(db.Model):
    """
    Records an executed simulation run in the Digital Twin environment.
    Stores aggregated confusion matrix, effectiveness scores, and AI recommendations.
    """
    __tablename__ = 'simulation_runs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    run_uuid = db.Column(db.String(64), nullable=False, unique=True, index=True)
    policy_id = db.Column(db.Integer, db.ForeignKey('virtual_policies.id', ondelete='SET NULL'), nullable=True)
    policy_name = db.Column(db.String(150), nullable=False)
    scenario_id = db.Column(db.Integer, db.ForeignKey('simulation_scenarios.id', ondelete='SET NULL'), nullable=True)
    scenario_name = db.Column(db.String(150), nullable=False)
    
    # Quantitative Results
    total_queries = db.Column(db.Integer, nullable=False, default=0)
    true_positives = db.Column(db.Integer, nullable=False, default=0)  # Correctly blocked threats
    false_positives = db.Column(db.Integer, nullable=False, default=0) # Benign mistakenly blocked
    true_negatives = db.Column(db.Integer, nullable=False, default=0)  # Legitimate correctly allowed
    false_negatives = db.Column(db.Integer, nullable=False, default=0) # Threats missed (allowed)
    
    # Derived Performance Metrics
    accuracy = db.Column(db.Float, nullable=False, default=0.0)
    precision = db.Column(db.Float, nullable=False, default=0.0)
    recall = db.Column(db.Float, nullable=False, default=0.0)
    f1_score = db.Column(db.Float, nullable=False, default=0.0)
    fpr = db.Column(db.Float, nullable=False, default=0.0)             # False Positive Rate
    fnr = db.Column(db.Float, nullable=False, default=0.0)             # False Negative Rate
    effectiveness_score = db.Column(db.Float, nullable=False, default=0.0) # Policy Effectiveness Score (0 - 100)
    
    execution_time_ms = db.Column(db.Float, nullable=False, default=0.0)
    recommendations_json = db.Column(db.Text, nullable=True)          # AI-generated recommendation cards
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False, index=True)

    items = db.relationship('SimulationItem', backref='run', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def recommendations(self):
        if not self.recommendations_json:
            return []
        try:
            return json.loads(self.recommendations_json)
        except Exception:
            return []

    @recommendations.setter
    def recommendations(self, value):
        if isinstance(value, list):
            self.recommendations_json = json.dumps(value)
        else:
            self.recommendations_json = json.dumps([])

    def to_dict(self, include_items=False):
        data = {
            'id': self.id,
            'runUuid': self.run_uuid,
            'policyId': self.policy_id,
            'policyName': self.policy_name,
            'scenarioId': self.scenario_id,
            'scenarioName': self.scenario_name,
            'totalQueries': self.total_queries,
            'confusionMatrix': {
                'truePositives': self.true_positives,
                'falsePositives': self.false_positives,
                'trueNegatives': self.true_negatives,
                'falseNegatives': self.false_negatives
            },
            'metrics': {
                'accuracy': round(self.accuracy, 2),
                'precision': round(self.precision, 2),
                'recall': round(self.recall, 2),
                'f1Score': round(self.f1_score, 2),
                'falsePositiveRate': round(self.fpr, 2),
                'falseNegativeRate': round(self.fnr, 2),
                'effectivenessScore': round(self.effectiveness_score, 2)
            },
            'executionTimeMs': round(self.execution_time_ms, 2),
            'recommendations': self.recommendations,
            'timestamp': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }
        if include_items:
            data['items'] = [item.to_dict() for item in self.items.all()]
        return data


class SimulationItem(db.Model):
    """
    Per-domain evaluation row within an isolated digital twin simulation run.
    Detailed telemetry for drill-down analysis, filtering, and false-positive root cause detection.
    """
    __tablename__ = 'simulation_items'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    run_id = db.Column(db.Integer, db.ForeignKey('simulation_runs.id', ondelete='CASCADE'), nullable=False, index=True)
    domain = db.Column(db.String(255), nullable=False)
    ground_truth = db.Column(db.String(30), nullable=False) # BENIGN, MALICIOUS, SUSPICIOUS
    simulated_action = db.Column(db.String(30), nullable=False) # ALLOWED, BLOCKED
    simulated_verdict = db.Column(db.String(30), nullable=False) # SAFE, MALICIOUS, SUSPICIOUS
    category = db.Column(db.String(100), nullable=True)
    classification_type = db.Column(db.String(10), nullable=False) # TP, FP, TN, FN
    is_correct = db.Column(db.Boolean, nullable=False)
    
    confidence_score = db.Column(db.Integer, nullable=False, default=0)
    entropy_score = db.Column(db.Float, nullable=True)
    trigger_rules_json = db.Column(db.Text, nullable=True) # Rules triggered (e.g. Entropy > 3.90, .top TLD, etc.)
    forensic_reason = db.Column(db.Text, nullable=True)
    latency_ms = db.Column(db.Float, default=1.2)

    @property
    def trigger_rules(self):
        if not self.trigger_rules_json:
            return []
        try:
            return json.loads(self.trigger_rules_json)
        except Exception:
            return [self.trigger_rules_json]

    @trigger_rules.setter
    def trigger_rules(self, value):
        if isinstance(value, list):
            self.trigger_rules_json = json.dumps(value)
        else:
            self.trigger_rules_json = json.dumps([str(value)] if value else [])

    def to_dict(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'groundTruth': self.ground_truth,
            'simulatedAction': self.simulated_action,
            'simulatedVerdict': self.simulated_verdict,
            'category': self.category or 'General',
            'classificationType': self.classification_type,
            'isCorrect': self.is_correct,
            'confidenceScore': self.confidence_score,
            'entropyScore': f"{self.entropy_score:.2f}" if self.entropy_score is not None else 'N/A',
            'triggerRules': self.trigger_rules,
            'reason': self.forensic_reason or '',
            'latencyMs': self.latency_ms
        }

