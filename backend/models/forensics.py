"""
AegisDNS - Attack Replay & Counterfactual Forensics Models
Database models for recorded security incidents, attack timeline events,
and counterfactual policy simulation analyses.
"""

from datetime import datetime, timezone
import json
from extensions import db


def utc_now():
    return datetime.now(timezone.utc)


class SecurityIncident(db.Model):
    """
    Recorded multi-stage DNS security incident or cyber campaign.
    Stores the full chronological attack timeline, ground truth, and historical system response.
    """
    __tablename__ = 'security_incidents'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    incident_code = db.Column(db.String(50), nullable=False, unique=True, index=True) # e.g. INC-8821
    title = db.Column(db.String(200), nullable=False)
    threat_actor = db.Column(db.String(120), nullable=False, default='Unknown Threat Actor') # e.g. APT-29 / CozyBear
    severity = db.Column(db.String(30), nullable=False, default='CRITICAL') # CRITICAL, HIGH, MEDIUM
    attack_vector = db.Column(db.String(150), nullable=False) # e.g. Spearphishing & DNS C2
    target_system = db.Column(db.String(150), nullable=False) # e.g. Finance Subnet Workstations
    attack_date = db.Column(db.DateTime, default=utc_now, nullable=False)
    
    # Forensic Historical Assessment
    original_outcome = db.Column(db.String(80), nullable=False) # e.g. 'Breach Occurred', 'Partially Contained'
    dwell_time_minutes = db.Column(db.Integer, nullable=False, default=45)
    total_events = db.Column(db.Integer, nullable=False, default=0)
    summary = db.Column(db.Text, nullable=False)
    impact_details = db.Column(db.Text, nullable=True)
    
    # JSON array of chronological event objects
    timeline_events_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)

    analyses = db.relationship('CounterfactualAnalysis', backref='incident', lazy='dynamic', cascade='all, delete-orphan')

    @property
    def timeline_events(self):
        if not self.timeline_events_json:
            return []
        try:
            return json.loads(self.timeline_events_json)
        except Exception:
            return []

    @timeline_events.setter
    def timeline_events(self, value):
        if isinstance(value, list):
            self.timeline_events_json = json.dumps(value)
            self.total_events = len(value)
        else:
            self.timeline_events_json = json.dumps([])
            self.total_events = 0

    def to_dict(self, include_events=True):
        data = {
            'id': self.id,
            'incidentCode': self.incident_code,
            'title': self.title,
            'threatActor': self.threat_actor,
            'severity': self.severity,
            'attackVector': self.attack_vector,
            'targetSystem': self.target_system,
            'attackDate': self.attack_date.strftime('%Y-%m-%d %H:%M:%S'),
            'originalOutcome': self.original_outcome,
            'dwellTimeMinutes': self.dwell_time_minutes,
            'totalEvents': self.total_events,
            'summary': self.summary,
            'impactDetails': self.impact_details or ''
        }
        if include_events:
            data['timelineEvents'] = self.timeline_events
        return data


class CounterfactualAnalysis(db.Model):
    """
    Stores counterfactual "what-if" evaluation results.
    Compares how a candidate virtual policy would have responded to a historical incident
    versus how the production system actually responded.
    """
    __tablename__ = 'counterfactual_analyses'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    analysis_uuid = db.Column(db.String(64), nullable=False, unique=True, index=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('security_incidents.id', ondelete='CASCADE'), nullable=False)
    policy_id = db.Column(db.Integer, db.ForeignKey('virtual_policies.id', ondelete='SET NULL'), nullable=True)
    policy_name = db.Column(db.String(150), nullable=False)
    
    # Differential Containment Metrics
    original_containment_step = db.Column(db.Integer, nullable=True) # e.g. Step 6
    counterfactual_containment_step = db.Column(db.Integer, nullable=True) # e.g. Step 2
    steps_accelerated = db.Column(db.Integer, nullable=False, default=0) # Original step - Counterfactual step
    time_saved_minutes = db.Column(db.Float, nullable=False, default=0.0)
    dwell_time_reduction_pct = db.Column(db.Float, nullable=False, default=0.0)
    
    # Verdicts
    breach_prevented = db.Column(db.Boolean, nullable=False, default=False)
    counterfactual_verdict = db.Column(db.String(80), nullable=False) # e.g. FULLY_PREVENTED, PARTIALLY_ACCELERATED, UNCHANGED
    damage_mitigation_score = db.Column(db.Float, nullable=False, default=0.0) # 0 to 100%
    
    # Telemetry payloads
    step_comparisons_json = db.Column(db.Text, nullable=False) # Side-by-side per-step evaluation
    recommendations_json = db.Column(db.Text, nullable=True)   # Remediation advice
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, default=utc_now, nullable=False)

    @property
    def step_comparisons(self):
        if not self.step_comparisons_json:
            return []
        try:
            return json.loads(self.step_comparisons_json)
        except Exception:
            return []

    @step_comparisons.setter
    def step_comparisons(self, value):
        if isinstance(value, list):
            self.step_comparisons_json = json.dumps(value)
        else:
            self.step_comparisons_json = json.dumps([])

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

    def to_dict(self):
        return {
            'id': self.id,
            'analysisUuid': self.analysis_uuid,
            'incidentId': self.incident_id,
            'policyId': self.policy_id,
            'policyName': self.policy_name,
            'metrics': {
                'originalContainmentStep': self.original_containment_step,
                'counterfactualContainmentStep': self.counterfactual_containment_step,
                'stepsAccelerated': self.steps_accelerated,
                'timeSavedMinutes': round(self.time_saved_minutes, 1),
                'dwellTimeReductionPct': round(self.dwell_time_reduction_pct, 1),
                'breachPrevented': self.breach_prevented,
                'verdict': self.counterfactual_verdict,
                'damageMitigationScore': round(self.damage_mitigation_score, 1)
            },
            'stepComparisons': self.step_comparisons,
            'recommendations': self.recommendations,
            'createdAt': self.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }

