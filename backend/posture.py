"""Validate minimal posture reports; do not retain command output or machine IDs."""
from datetime import datetime,timezone
from typing import Literal

from pydantic import BaseModel,ConfigDict,Field,model_validator

from .scanner import finding

CHECKS={'firewall_domain','firewall_private','firewall_public','defender','system_disk'}
MAC_CHECKS={'application_firewall','filevault','gatekeeper'}


class Check(BaseModel):
    model_config=ConfigDict(extra='forbid')
    id: Literal['firewall_domain','firewall_private','firewall_public','defender','system_disk','application_firewall','filevault','gatekeeper']
    state: Literal['enabled','disabled','passive','unassessed','unsupported']
    reason: Literal['','permission_denied','command_unavailable','timeout','provider_error','invalid_response','unknown_status','unsupported_platform']=''

    @model_validator(mode='after')
    def valid_state(self):
        if self.state=='passive' and self.id!='defender' or self.state in {'enabled','disabled','passive'} and self.reason or self.state=='unassessed' and self.reason not in {'permission_denied','command_unavailable','timeout','provider_error','invalid_response','unknown_status'} or self.state=='unsupported' and self.reason!='unsupported_platform':
            raise ValueError('Invalid posture state/reason combination')
        return self


class Report(BaseModel):
    model_config=ConfigDict(extra='forbid')
    version: Literal[1,2]
    platform: Literal['windows','linux','macos','other']
    generated_at: str=Field(max_length=40)
    checks: list[Check]=Field(min_length=3,max_length=5)

    @model_validator(mode='after')
    def complete(self):
        mac=self.version==2 and self.platform=='macos'
        valid=mac and len(self.checks)==3 and {item.id for item in self.checks}==MAC_CHECKS and all(item.state in {'enabled','disabled','unassessed'} for item in self.checks) or self.version==1 and len(self.checks)==5 and {item.id for item in self.checks}==CHECKS and (self.platform=='windows' or all(item.state=='unsupported' for item in self.checks))
        if not valid:
            raise ValueError('Posture report requires all supported check identifiers')
        try:
            timestamp=datetime.fromisoformat(self.generated_at)
            if timestamp.tzinfo is None or not -300<=(datetime.now(timezone.utc)-timestamp).total_seconds()<=3600:
                raise ValueError()
        except ValueError:
            raise ValueError('Posture report timestamp is invalid or stale')
        return self


def assessment(report,paired=False):
    report=report if isinstance(report,Report) else Report.model_validate(report)
    if report.platform=='macos' and report.version==2:
        partial=any(check.state=='unassessed' for check in report.checks)
        return {'findings':[],'posture':report.model_dump(),'observations':[],'error':'Some macOS protection checks could not be assessed.' if partial else None,'limits':'Fixed read-only macOS application-firewall, FileVault and Gatekeeper status. Check the recorded states, including disabled protections; zero scanner findings is not a healthy-device verdict. No firewall rules, disk recovery keys, malware, updates, external exposure or compliance were assessed. No configuration changed. Helper self-report, not independent attestation.'}
    items=[]
    for check in report.checks:
        if check.state=='disabled':
            rule='HOST001' if check.id.startswith('firewall_') else 'HOST002' if check.id=='defender' else 'HOST003'
            evidence={'HOST001':'Windows reports this firewall profile as disabled. Whether the profile is currently active and which rules apply were not assessed.','HOST002':'Microsoft Defender reports antivirus or real-time protection disabled. Another security product may be active; overall antivirus protection is not established.','HOST003':'System-drive BitLocker reports protection off. Encryption may be suspended or unavailable; no recovery key was read and other volumes were not assessed.'}[rule]
            items.append(finding(rule,evidence=evidence,confidence='low' if paired else 'medium',posture_check=check.id))
    partial=any(check.state in {'unassessed','unsupported'} for check in report.checks)
    return {'findings':items,'posture':report.model_dump(),'observations':[],'error':'Some host protection checks were unavailable or unsupported; review coverage.' if partial else None,'limits':'Fixed read-only Windows protection status checks on the operator computer only. Firewall profile configuration is not active-path/rule analysis. Defender status does not assess other antivirus products. BitLocker status covers only system-drive protection, not recovery keys or every disk. No patch, software, process, compliance or compromise assessment; no settings changed.'+(' Paired-device self-report, not independent attestation.' if paired else '')}
