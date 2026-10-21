"""Typed minimal cached Windows Update observations, never patch compliance."""
from datetime import datetime,timezone
from typing import Literal
from pydantic import BaseModel,ConfigDict,Field,model_validator
from .scanner import finding

REASONS={'permission_denied','command_unavailable','timeout','provider_error','invalid_response','unknown_status','unsupported_platform'}

class Observation(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    state:Literal['observed','unassessed','unsupported']
    reason:Literal['','permission_denied','command_unavailable','timeout','provider_error','invalid_response','unknown_status','unsupported_platform']=''

    @model_validator(mode='after')
    def reason_matches(self):
        if self.state=='observed' and self.reason or self.state=='unassessed' and self.reason not in REASONS-{'unsupported_platform'} or self.state=='unsupported' and self.reason!='unsupported_platform':
            raise ValueError('Invalid update observation state/reason')
        return self

class Cache(Observation):
    pending:int|None=Field(default=None,ge=0,le=10000)
    security:int|None=Field(default=None,ge=0,le=10000)

    @model_validator(mode='after')
    def counts_match(self):
        if self.state=='observed':
            if self.pending is None or self.security is None or self.security>self.pending:raise ValueError('Invalid cached update counts')
        elif self.pending is not None or self.security is not None:raise ValueError('Unassessed counts must be absent')
        return self

class Reboot(Observation):
    required:bool|None=None

    @model_validator(mode='after')
    def value_matches(self):
        if (self.required is None)==(self.state=='observed'):raise ValueError('Invalid reboot observation')
        return self

class Report(BaseModel):
    model_config=ConfigDict(extra='forbid',strict=True)
    version:Literal[1]
    platform:Literal['windows','linux','macos','other']
    generated_at:str=Field(max_length=40)
    source:Literal['windows-update-offline-cache']
    cache:Cache
    reboot:Reboot

    @model_validator(mode='after')
    def valid(self):
        stamp=datetime.fromisoformat(self.generated_at)
        if stamp.tzinfo is None or not -300<=(datetime.now(timezone.utc)-stamp).total_seconds()<=3600:raise ValueError('Stale update report')
        if self.platform!='windows' and any(item.state!='unsupported' for item in (self.cache,self.reboot)):raise ValueError('Unsupported platform must stay unsupported')
        if self.platform=='windows' and any(item.state=='unsupported' for item in (self.cache,self.reboot)):raise ValueError('Windows provider errors must stay unassessed')
        return self


def assessment(value,paired=False):
    report=value if isinstance(value,Report) else Report.model_validate(value)
    findings=[]
    if report.cache.state=='observed' and report.cache.security:
        findings.append(finding('UPD001',evidence='The offline Windows Update cache reports one or more pending security/critical-classified software updates. Cache freshness and actual patch exposure were not established.',confidence='low'))
    if report.reboot.state=='observed' and report.reboot.required:
        findings.append(finding('UPD002',evidence='Windows Update reports that a restart is required to complete an update installation or removal. No restart was initiated.',confidence='low' if paired else 'medium'))
    partial=any(item.state!='observed' for item in (report.cache,report.reboot))
    return dict(findings=findings,updates=report.model_dump(),observations=[],error='Some Windows Update observations could not be assessed.' if partial else None,limits='Read-only Windows Update offline cache and update-related reboot status on the selected operator computer. Cached unhidden software updates only; no online catalog refresh, driver/hidden update coverage, installed-patch inventory, third-party software, support-lifecycle or CVE assessment. Cache freshness is unknown; zero cached updates does not mean fully patched. No updates installed, downloads, reboot or settings changes.'+(' Paired-device self-report, not attestation.' if paired else ''))
