"""
AegisDNS - Attack Replay & Counterfactual Security Forensics Service
Simulates historical attack timelines, evaluates kill-chain progression,
and performs counterfactual policy analysis to measure dwell time reduction and breach prevention.
"""

import uuid
import time
from datetime import datetime, timezone
from extensions import db
from models.forensics import SecurityIncident, CounterfactualAnalysis
from models.digital_twin import VirtualPolicy
from services.digital_twin_service import DigitalTwinService


def utc_now():
    return datetime.now(timezone.utc)


class ForensicsService:
    """
    Forensic analysis engine for replaying historical DNS security incidents
    and performing counterfactual "what-if" policy evaluations.
    """

    @classmethod
    def seed_default_incidents(cls):
        """
        Seeds standard historical security incident cases with step-by-step kill-chain timelines.
        """
        incidents_data = [
            {
                'incident_code': 'INC-8821',
                'title': 'APT-29 SolarFlare Phishing & Multi-Stage C2 Infiltration',
                'threat_actor': 'APT-29 / CozyBear (State-Sponsored)',
                'severity': 'CRITICAL',
                'attack_vector': 'Spearphishing Email -> Staged C2 Beaconing -> Lateral Lookup',
                'target_system': 'Finance & Executive Workstation Subnet (192.168.1.100-150)',
                'dwell_time_minutes': 48,
                'original_outcome': 'Breach Occurred & C2 Channel Established',
                'summary': 'Targeted multi-stage advanced threat campaign. The attacker bypassed initial lexical checks using deceptive branding on .online, established encrypted C2 beaconing, and performed internal lateral reconnaissance before late manual sinkholing.',
                'impact_details': 'Initial access credentials harvested; active C2 beacon sustained for 48 minutes; 14 internal host records queried.',
                'timeline_events': [
                    {
                        'step': 1,
                        'offsetSec': 0,
                        'domain': 'update-check.microsoft-telemetry.cc',
                        'queryType': 'A',
                        'clientIp': '192.168.1.115',
                        'groundTruth': 'SUSPICIOUS',
                        'originalAction': 'ALLOWED',
                        'originalVerdict': 'SAFE',
                        'killChainPhase': 'Reconnaissance',
                        'threatDetails': 'Subtle deceptive brand spoofing. Unverified on public feeds during early probe.',
                        'historicalImpact': 'Attacker verified target subnet resolves external DNS without active challenge.'
                    },
                    {
                        'step': 2,
                        'offsetSec': 180,
                        'domain': 'azure-sync-ad-connector.online',
                        'queryType': 'A',
                        'clientIp': '192.168.1.115',
                        'groundTruth': 'MALICIOUS',
                        'originalAction': 'ALLOWED',
                        'originalVerdict': 'SAFE',
                        'killChainPhase': 'Weaponized Delivery / Phishing',
                        'threatDetails': 'Credential harvesting landing page masquerading as Azure AD single sign-on.',
                        'historicalImpact': 'Victim workstation downloaded weaponized dropper payload.'
                    },
                    {
                        'step': 3,
                        'offsetSec': 620,
                        'domain': 'x8k2m9v4q1.biz',
                        'queryType': 'A',
                        'clientIp': '192.168.1.115',
                        'groundTruth': 'MALICIOUS',
                        'originalAction': 'ALLOWED',
                        'originalVerdict': 'SUSPICIOUS',
                        'killChainPhase': 'DGA Secondary Beacon',
                        'threatDetails': 'Pseudorandom DGA rendezvous domain with Shannon entropy 3.84.',
                        'historicalImpact': 'Payload obtained secondary dynamic IP controller address.'
                    },
                    {
                        'step': 4,
                        'offsetSec': 1440,
                        'domain': 'c2-trojan-controller-sync.net',
                        'queryType': 'A',
                        'clientIp': '192.168.1.115',
                        'groundTruth': 'MALICIOUS',
                        'originalAction': 'ALLOWED',
                        'originalVerdict': 'SUSPICIOUS',
                        'killChainPhase': 'C2 Channel Establishment',
                        'threatDetails': 'Cobalt Strike malleable C2 interactive session initiation.',
                        'historicalImpact': 'Active shell access established; operator commenced host enumeration.'
                    },
                    {
                        'step': 5,
                        'offsetSec': 2100,
                        'domain': 'corp-dc01-active-directory.local',
                        'queryType': 'SRV',
                        'clientIp': '192.168.1.115',
                        'groundTruth': 'BENIGN',
                        'originalAction': 'ALLOWED',
                        'originalVerdict': 'SAFE',
                        'killChainPhase': 'Lateral Reconnaissance',
                        'threatDetails': 'Internal Active Directory service record query executed by threat agent.',
                        'historicalImpact': 'Primary domain controller located on corporate network.'
                    },
                    {
                        'step': 6,
                        'offsetSec': 2880,
                        'domain': 'stage2-payload-exfil.top',
                        'queryType': 'A',
                        'clientIp': '192.168.1.115',
                        'groundTruth': 'MALICIOUS',
                        'originalAction': 'BLOCKED',
                        'originalVerdict': 'MALICIOUS',
                        'killChainPhase': 'Exfiltration Staging',
                        'threatDetails': 'Known malicious infostealer endpoint; matched late signature feed update.',
                        'historicalImpact': 'Late containment: Query sinkholed to 0.0.0.0, but credential harvesting had already completed.'
                    }
                ]
            },
            {
                'incident_code': 'INC-8822',
                'title': 'DarkSide Ransomware Pre-Encryption Outbreak',
                'threat_actor': 'DarkSide Ransomware Syndicate',
                'severity': 'CRITICAL',
                'attack_vector': 'Malvertising Drive-by -> Dynamic DNS Key Exchange -> Volume Shadow Drop',
                'target_system': 'Billing & Payroll Database Host (192.168.1.142)',
                'dwell_time_minutes': 34,
                'original_outcome': 'Partial Subnet Encryption Before Containment',
                'summary': 'High-velocity ransomware deployment. Initial malicious redirect on .top was allowed due to permissive TLD rules. The malware established asymmetric key exchange with dynamic DNS controllers, detonating encryption across 3 networked shared drives before late sinkholing.',
                'impact_details': '3 shared network folders encrypted; backup shadow copies targeted; incident response engaged after user ticket.',
                'timeline_events': [
                    {
                        'step': 1,
                        'offsetSec': 0,
                        'domain': 'secure-document-portal-view.top',
                        'queryType': 'A',
                        'clientIp': '192.168.1.142',
                        'groundTruth': 'MALICIOUS',
                        'originalAction': 'ALLOWED',
                        'originalVerdict': 'SAFE',
                        'killChainPhase': 'Initial Delivery',
                        'threatDetails': 'Malvertising lure hosted on high-abuse .top TLD.',
                        'historicalImpact': 'Browser silently downloaded Stage 1 loader script.'
                    },
                    {
                        'step': 2,
                        'offsetSec': 240,
                        'domain': 'malware-payload-stage1.biz',
                        'queryType': 'A',
                        'clientIp': '192.168.1.142',
                        'groundTruth': 'MALICIOUS',
                        'originalAction': 'ALLOWED',
                        'originalVerdict': 'SAFE',
                        'killChainPhase': 'Payload Download',
                        'threatDetails': 'Encrypted binary dropper download endpoint.',
                        'historicalImpact': 'Ransomware executable written to %APPDATA% directory.'
                    },
                    {
                        'step': 3,
                        'offsetSec': 780,
                        'domain': 'p9o8i7u6y5t4r3.biz',
                        'queryType': 'A',
                        'clientIp': '192.168.1.142',
                        'groundTruth': 'MALICIOUS',
                        'originalAction': 'ALLOWED',
                        'originalVerdict': 'SUSPICIOUS',
                        'killChainPhase': 'Key Exchange C2',
                        'threatDetails': 'High-entropy algorithmic controller negotiated master encryption public key.',
                        'historicalImpact': 'Symmetric AES-256 session key generated and bound to local machine GUID.'
                    },
                    {
                        'step': 4,
                        'offsetSec': 1200,
                        'domain': 'ransomware-negotiation-portal.cc',
                        'queryType': 'A',
                        'clientIp': '192.168.1.142',
                        'groundTruth': 'MALICIOUS',
                        'originalAction': 'ALLOWED',
                        'originalVerdict': 'SUSPICIOUS',
                        'killChainPhase': 'Ransom Note Staging',
                        'threatDetails': 'TOR proxy negotiation mirror.',
                        'historicalImpact': 'Ransom instructions rendered to victim desktop.'
                    },
                    {
                        'step': 5,
                        'offsetSec': 1680,
                        'domain': 'dc-backup-controller.lan',
                        'queryType': 'A',
                        'clientIp': '192.168.1.142',
                        'groundTruth': 'BENIGN',
                        'originalAction': 'ALLOWED',
                        'originalVerdict': 'SAFE',
                        'killChainPhase': 'Internal Shared Storage',
                        'threatDetails': 'Legitimate internal storage volume mapped via SMB.',
                        'historicalImpact': 'File encryption initiated across local drives and network shares.'
                    },
                    {
                        'step': 6,
                        'offsetSec': 2040,
                        'domain': 'darkside-drop-vault.ru',
                        'queryType': 'A',
                        'clientIp': '192.168.1.142',
                        'groundTruth': 'MALICIOUS',
                        'originalAction': 'BLOCKED',
                        'originalVerdict': 'MALICIOUS',
                        'killChainPhase': 'Exfiltration Channel',
                        'threatDetails': 'Targeted by emergency SecOps sinkhole policy rule.',
                        'historicalImpact': 'Exfiltration halted at Step 6, but encryption damage had already occurred.'
                    }
                ]
            },
            {
                'incident_code': 'INC-8823',
                'title': 'Covert DNS Tunneling & Customer Data Exfiltration',
                'threat_actor': 'FIN7 / Carbanak Financial Syndicate',
                'severity': 'HIGH',
                'attack_vector': 'Base64 Subdomain DNS Tunneling (Slow & Low)',
                'target_system': 'Point-of-Sale / E-Commerce Backend (192.168.1.205)',
                'dwell_time_minutes': 65,
                'original_outcome': '14,200 Customer Payment Records Exfiltrated',
                'summary': 'Covert low-frequency data exfiltration leveraging encoded DNS queries. Because standard DNS packet filtering did not enforce subdomain depth or character entropy thresholds on subdomains, 18 sequential chunks bypassed detection until firewall netflow alerts triggered.',
                'impact_details': 'Payment card tokens and customer PII exfiltrated in TXT and A query subdomains.',
                'timeline_events': [
                    {
                        'step': 1,
                        'offsetSec': 0,
                        'domain': 'tunnel-gateway.dns-tunnel-drop.xyz',
                        'queryType': 'TXT',
                        'clientIp': '192.168.1.205',
                        'groundTruth': 'MALICIOUS',
                        'originalAction': 'ALLOWED',
                        'originalVerdict': 'SAFE',
                        'killChainPhase': 'Tunnel Handshake',
                        'threatDetails': 'Initial tunneling protocol sync packet with Base64 signature.',
                        'historicalImpact': 'Tunnel established; threat agent verified bidirectional DNS encoding.'
                    },
                    {
                        'step': 2,
                        'offsetSec': 420,
                        'domain': 'dG9rZW4xMjM0NTY3OA.tunnel-gateway.dns-tunnel-drop.xyz',
                        'queryType': 'A',
                        'clientIp': '192.168.1.205',
                        'groundTruth': 'MALICIOUS',
                        'originalAction': 'ALLOWED',
                        'originalVerdict': 'SAFE',
                        'killChainPhase': 'Data Exfiltration (Chunk 01)',
                        'threatDetails': 'Base64 encoded customer record batch 1. Entropy: 4.15.',
                        'historicalImpact': '2,400 records exfiltrated covertly.'
                    },
                    {
                        'step': 3,
                        'offsetSec': 960,
                        'domain': 'cGFzc3dvcmQxMjM0NTY.tunnel-gateway.dns-tunnel-drop.xyz',
                        'queryType': 'A',
                        'clientIp': '192.168.1.205',
                        'groundTruth': 'MALICIOUS',
                        'originalAction': 'ALLOWED',
                        'originalVerdict': 'SAFE',
                        'killChainPhase': 'Data Exfiltration (Chunk 02)',
                        'threatDetails': 'Base64 encoded customer record batch 2. Entropy: 4.22.',
                        'historicalImpact': '3,100 additional records leaked.'
                    },
                    {
                        'step': 4,
                        'offsetSec': 1680,
                        'domain': 'Y3JjMTZzdW1jaGVja2RhdGE.tunnel-gateway.dns-tunnel-drop.xyz',
                        'queryType': 'A',
                        'clientIp': '192.168.1.205',
                        'groundTruth': 'MALICIOUS',
                        'originalAction': 'ALLOWED',
                        'originalVerdict': 'SAFE',
                        'killChainPhase': 'Data Exfiltration (Chunk 03)',
                        'threatDetails': 'Base64 encoded customer record batch 3. Entropy: 4.18.',
                        'historicalImpact': '4,200 records leaked.'
                    },
                    {
                        'step': 5,
                        'offsetSec': 2520,
                        'domain': 'ZW5jcnlwdGVkYmF0Y2gwNA.tunnel-gateway.dns-tunnel-drop.xyz',
                        'queryType': 'A',
                        'clientIp': '192.168.1.205',
                        'groundTruth': 'MALICIOUS',
                        'originalAction': 'ALLOWED',
                        'originalVerdict': 'SAFE',
                        'killChainPhase': 'Data Exfiltration (Chunk 04)',
                        'threatDetails': 'Base64 encoded customer record batch 4. Entropy: 4.19.',
                        'historicalImpact': '4,500 records leaked (Cumulative: 14,200).'
                    },
                    {
                        'step': 6,
                        'offsetSec': 3900,
                        'domain': 'tunnel-gateway.dns-tunnel-drop.xyz',
                        'queryType': 'A',
                        'clientIp': '192.168.1.205',
                        'groundTruth': 'MALICIOUS',
                        'originalAction': 'BLOCKED',
                        'originalVerdict': 'MALICIOUS',
                        'killChainPhase': 'Emergency Containment',
                        'threatDetails': 'Manual administrator domain sinkhole rule applied after firewall alert.',
                        'historicalImpact': 'Tunnel disconnected after 65 minutes. Breach had already transpired.'
                    }
                ]
            }
        ]

        for inc_data in incidents_data:
            code = inc_data['incident_code']
            existing = SecurityIncident.query.filter_by(incident_code=code).first()
            if not existing:
                inc = SecurityIncident(
                    incident_code=code,
                    title=inc_data['title'],
                    threat_actor=inc_data['threat_actor'],
                    severity=inc_data['severity'],
                    attack_vector=inc_data['attack_vector'],
                    target_system=inc_data['target_system'],
                    dwell_time_minutes=inc_data['dwell_time_minutes'],
                    original_outcome=inc_data['original_outcome'],
                    summary=inc_data['summary'],
                    impact_details=inc_data['impact_details'],
                    timeline_events=inc_data['timeline_events']
                )
                db.session.add(inc)
            else:
                existing.title = inc_data['title']
                existing.threat_actor = inc_data['threat_actor']
                existing.severity = inc_data['severity']
                existing.attack_vector = inc_data['attack_vector']
                existing.target_system = inc_data['target_system']
                existing.dwell_time_minutes = inc_data['dwell_time_minutes']
                existing.original_outcome = inc_data['original_outcome']
                existing.summary = inc_data['summary']
                existing.impact_details = inc_data['impact_details']
                existing.timeline_events = inc_data['timeline_events']

        db.session.commit()

    @classmethod
    def get_incidents(cls) -> list:
        """Returns list of recorded security incidents"""
        cls.seed_default_incidents()
        incidents = SecurityIncident.query.order_by(SecurityIncident.id.asc()).all()
        return [i.to_dict(include_events=False) for i in incidents]

    @classmethod
    def get_incident_details(cls, incident_id: int) -> dict:
        """Returns complete forensic incident record with timeline events"""
        cls.seed_default_incidents()
        incident = db.session.get(SecurityIncident, incident_id)
        if not incident:
            raise ValueError(f"Security Incident with ID {incident_id} not found.")
        return incident.to_dict(include_events=True)

    @classmethod
    def run_counterfactual_analysis(cls, incident_id: int, policy_id: int, user_id: int = None) -> dict:
        """
        Executes counterfactual "what-if" evaluation.
        Evaluates each chronological attack event against candidate VirtualPolicy parameters,
        pinpoints the exact step where the candidate policy would have severed the kill chain,
        and computes dwell time reduction and breach prevention statistics.
        """
        cls.seed_default_incidents()
        incident = db.session.get(SecurityIncident, incident_id)
        if not incident:
            raise ValueError(f"Security Incident with ID {incident_id} not found.")

        policy = db.session.get(VirtualPolicy, policy_id)
        if not policy:
            policy = DigitalTwinService.get_or_create_baseline_policy()

        events = incident.timeline_events
        if not events:
            raise ValueError("Incident timeline has no recorded events.")

        # Replay each event against the candidate policy
        step_comparisons = []
        original_containment_step = None
        counterfactual_containment_step = None

        for event in events:
            step_num = event.get('step', 1)
            offset_sec = event.get('offsetSec', 0)
            domain = event.get('domain', '')
            ground_truth = event.get('groundTruth', 'MALICIOUS')
            orig_action = event.get('originalAction', 'ALLOWED')
            orig_verdict = event.get('originalVerdict', 'SAFE')
            phase = event.get('killChainPhase', 'Execution')
            threat_details = event.get('threatDetails', '')

            # Check original containment
            if orig_action == 'BLOCKED' and original_containment_step is None:
                original_containment_step = step_num

            # Counterfactual evaluation using DigitalTwin feature extractor
            sim_record = {
                'domain': domain,
                'groundTruth': ground_truth,
                'category': phase,
                'iocDetails': threat_details
            }
            eval_result = DigitalTwinService.evaluate_domain_against_policy(sim_record, policy)

            cf_action = eval_result['simulatedAction']
            cf_verdict = eval_result['simulatedVerdict']
            cf_trigger_rules = eval_result['triggerRules']
            cf_confidence = eval_result['confidenceScore']

            # Check counterfactual containment (earliest step where threat is blocked)
            if cf_action == 'BLOCKED' and counterfactual_containment_step is None and ground_truth in ['MALICIOUS', 'SUSPICIOUS']:
                counterfactual_containment_step = step_num

            # Determine kill-chain status for this step
            is_threat = ground_truth in ['MALICIOUS', 'SUSPICIOUS']
            if is_threat:
                if orig_action == 'ALLOWED' and cf_action == 'BLOCKED':
                    step_status = 'PREVENTED_BY_POLICY' # Significant improvement!
                elif orig_action == 'BLOCKED' and cf_action == 'BLOCKED':
                    step_status = 'REDUNDANT_BLOCKED'
                elif orig_action == 'ALLOWED' and cf_action == 'ALLOWED':
                    step_status = 'MISSED_BY_BOTH'
                else:
                    step_status = 'REGRESSION_ALLOWED'
            else:
                step_status = 'BENIGN_TRAFFIC'

            step_comparisons.append({
                'step': step_num,
                'offsetSec': offset_sec,
                'domain': domain,
                'queryType': event.get('queryType', 'A'),
                'clientIp': event.get('clientIp', '192.168.1.115'),
                'groundTruth': ground_truth,
                'killChainPhase': phase,
                'threatDetails': threat_details,
                'original': {
                    'action': orig_action,
                    'verdict': orig_verdict,
                    'impact': event.get('historicalImpact', '')
                },
                'counterfactual': {
                    'action': cf_action,
                    'verdict': cf_verdict,
                    'triggerRules': cf_trigger_rules,
                    'confidenceScore': cf_confidence,
                    'reason': eval_result['reason']
                },
                'stepStatus': step_status
            })

        # Default fallback containment if never blocked
        if original_containment_step is None:
            original_containment_step = len(events)
        if counterfactual_containment_step is None:
            counterfactual_containment_step = len(events)

        # Acceleration and Dwell Time Math
        steps_accelerated = max(0, original_containment_step - counterfactual_containment_step)
        
        # Calculate time saved from offset seconds
        orig_contain_sec = 0
        cf_contain_sec = 0
        for ev in events:
            if ev.get('step') == original_containment_step:
                orig_contain_sec = ev.get('offsetSec', 0)
            if ev.get('step') == counterfactual_containment_step:
                cf_contain_sec = ev.get('offsetSec', 0)

        time_saved_sec = max(0, orig_contain_sec - cf_contain_sec)
        time_saved_minutes = time_saved_sec / 60.0
        
        dwell_reduction_pct = ((orig_contain_sec - cf_contain_sec) / orig_contain_sec * 100.0) if orig_contain_sec > 0 else 0.0
        dwell_reduction_pct = max(0.0, min(100.0, dwell_reduction_pct))

        # Breach Prevention Classification
        # If contained at or before delivery/phishing/first C2 (Step <= 2)
        breach_prevented = (counterfactual_containment_step <= 2)
        if breach_prevented:
            cf_verdict_str = 'BREACH_FULLY_PREVENTED'
            damage_score = 100.0
        elif steps_accelerated > 0:
            cf_verdict_str = 'PARTIALLY_CONTAINED_EARLY'
            damage_score = 50.0 + (steps_accelerated * 12.5)
        else:
            cf_verdict_str = 'NO_CONTAINMENT_IMPROVEMENT'
            damage_score = 10.0

        damage_score = min(100.0, damage_score)

        # Generate Contextual Forensic Recommendations
        recommendations = cls._generate_counterfactual_recommendations(
            incident, policy, counterfactual_containment_step, original_containment_step, step_comparisons
        )

        # Persist Analysis Record
        analysis_uuid = f"CFA-{uuid.uuid4().hex[:8].upper()}"
        analysis_record = CounterfactualAnalysis(
            analysis_uuid=analysis_uuid,
            incident_id=incident.id,
            policy_id=policy.id,
            policy_name=policy.name,
            original_containment_step=original_containment_step,
            counterfactual_containment_step=counterfactual_containment_step,
            steps_accelerated=steps_accelerated,
            time_saved_minutes=time_saved_minutes,
            dwell_time_reduction_pct=dwell_reduction_pct,
            breach_prevented=breach_prevented,
            counterfactual_verdict=cf_verdict_str,
            damage_mitigation_score=damage_score,
            step_comparisons=step_comparisons,
            recommendations=recommendations,
            user_id=user_id
        )
        db.session.add(analysis_record)
        db.session.commit()

        return {
            'success': True,
            'analysisId': analysis_record.id,
            'analysisUuid': analysis_record.analysis_uuid,
            'incident': incident.to_dict(include_events=False),
            'policy': policy.to_dict(),
            'metrics': {
                'originalContainmentStep': original_containment_step,
                'counterfactualContainmentStep': counterfactual_containment_step,
                'stepsAccelerated': steps_accelerated,
                'timeSavedMinutes': round(time_saved_minutes, 1),
                'dwellTimeReductionPct': round(dwell_reduction_pct, 1),
                'breachPrevented': breach_prevented,
                'verdict': cf_verdict_str,
                'damageMitigationScore': round(damage_score, 1)
            },
            'stepComparisons': step_comparisons,
            'recommendations': recommendations
        }

    @classmethod
    def _generate_counterfactual_recommendations(cls, incident: SecurityIncident, policy: VirtualPolicy, cf_step: int, orig_step: int, steps: list) -> list:
        """
        Synthesizes forensic root-cause insights explaining why the historical breach occurred
        and actionable recommendations to enforce early containment.
        """
        recs = []

        if cf_step <= 2:
            recs.append({
                'id': 'REC-EARLY-CONTAIN',
                'severity': 'CRITICAL_FIX',
                'title': 'Pre-Execution Kill-Chain Severance Confirmed',
                'finding': f"Under policy '{policy.name}', the attack was severed at Step {cf_step} (Delivery Phase), prior to payload execution or C2 channel establishment.",
                'actionableStep': 'Promote this candidate virtual policy to live protection to prevent identical spearphishing vectors.',
                'impact': f"-{incident.dwell_time_minutes} min dwell time (100% data loss eliminated)"
            })
        else:
            recs.append({
                'id': 'REC-TIGHTEN-TLD',
                'severity': 'HIGH',
                'title': 'Enforce TLD and Lexical Heuristics on Initial Lure Domains',
                'finding': f"The attack progressed to Step {cf_step} before containment. The adversary leveraged unverified TLDs during early recon.",
                'actionableStep': f"Lower Shannon entropy cutoff to 3.75 and add high-risk TLDs (.online, .top, .cc, .biz) to restricted policy rules.",
                'impact': 'Accelerates containment to Step 1'
            })

        recs.append({
            'id': 'REC-C2-SINKHOLE',
            'severity': 'MEDIUM',
            'title': 'Automate Real-Time 0.0.0.0 Sinkhole Synchronization',
            'finding': f"In the historical incident, Step {orig_step} required manual SecOps intervention. Automated sinkholing would have prevented post-compromise lateral queries.",
            'actionableStep': 'Ensure automated domain blocking (auto_block=true) is synchronized with upstream threat intelligence feeds.',
            'impact': 'Eliminates human delay during active beaconing'
        })

        return recs

    @classmethod
    def get_analysis_report(cls, analysis_id: int) -> dict:
        """
        Retrieves detailed forensic report for export.
        """
        cls.seed_default_incidents()
        analysis = db.session.get(CounterfactualAnalysis, analysis_id)
        if not analysis:
            raise ValueError(f"Counterfactual Analysis with ID {analysis_id} not found.")

        incident = db.session.get(SecurityIncident, analysis.incident_id)
        policy = db.session.get(VirtualPolicy, analysis.policy_id) if analysis.policy_id else None

        return {
            'reportTitle': 'AegisDNS Forensic Incident & Counterfactual Security Audit Report',
            'analysisUuid': analysis.analysis_uuid,
            'generatedAt': analysis.created_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'incident': incident.to_dict(include_events=False) if incident else {},
            'evaluatedPolicy': policy.to_dict() if policy else {'name': analysis.policy_name},
            'executiveSummary': {
                'historicalOutcome': incident.original_outcome if incident else 'Breach Occurred',
                'counterfactualOutcome': analysis.counterfactual_verdict,
                'originalContainmentPoint': f"Step {analysis.original_containment_step}",
                'counterfactualContainmentPoint': f"Step {analysis.counterfactual_containment_step}",
                'dwellTimeReduction': f"{analysis.dwell_time_reduction_pct:.1f}%",
                'timeSavedMinutes': f"{analysis.time_saved_minutes:.1f} minutes",
                'breachPrevented': analysis.breach_prevented,
                'damageMitigationScore': f"{analysis.damage_mitigation_score:.1f}%"
            },
            'stepTimelineComparisons': analysis.step_comparisons,
            'remediationRecommendations': analysis.recommendations
        }

