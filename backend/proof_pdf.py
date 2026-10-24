"""Self-contained PDF renderer. No remote assets, active links or raw scan data."""
from io import BytesIO
from datetime import datetime,timezone
from pathlib import Path
from xml.sax.saxutils import escape
import threading
import reportlab
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,LongTable,TableStyle

LOCK=threading.Lock()

def fonts():
    with LOCK:
        if 'ProofSans' not in pdfmetrics.getRegisteredFontNames():
            root=Path(reportlab.__file__).parent/'fonts'
            pdfmetrics.registerFont(TTFont('ProofSans',str(root/'Vera.ttf')))
            pdfmetrics.registerFont(TTFont('ProofSansBold',str(root/'VeraBd.ttf')))

def render(report):
    fonts();out=BytesIO();green=colors.HexColor('#245746');muted=colors.HexColor('#52655e')
    base=ParagraphStyle('body',fontName='ProofSans',fontSize=8.5,leading=12,textColor=colors.HexColor('#20352d'),spaceAfter=6,wordWrap='CJK')
    small=ParagraphStyle('small',parent=base,fontSize=7,leading=10,textColor=muted)
    heading=ParagraphStyle('heading',parent=base,fontName='ProofSansBold',fontSize=14,leading=19,spaceBefore=16,spaceAfter=8,textColor=green,keepWithNext=True)
    title=ParagraphStyle('title',parent=heading,fontSize=27,leading=34,spaceBefore=4)
    supported=pdfmetrics.getFont('ProofSans').face.charToGlyph
    def text(value):
        raw=str(value if value is not None else 'Not recorded')
        raw=''.join(ch if ord(ch) in supported or ch in '\n\t' else '[U+%04X]'%ord(ch) for ch in raw)
        return escape(raw).replace('\n','<br/>')
    def p(value,style=base):return Paragraph(text(value),style)
    story=[]
    def section(name,description=None):
        story.append(p(name,heading))
        if description:story.append(p(description,small))
    def table(headers,rows,widths):
        if not rows:story.append(p('No records in the selected scope.',small));return
        data=[[p(v,small) for v in headers]]+[[p(v,small) for v in row] for row in rows]
        item=LongTable(data,colWidths=widths,repeatRows=1,hAlign='LEFT',splitByRow=1)
        item.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#e8f0e8')),('VALIGN',(0,0),(-1,-1),'TOP'),('TOPPADDING',(0,0),(-1,-1),7),('BOTTOMPADDING',(0,0),(-1,-1),7),('LEFTPADDING',(0,0),(-1,-1),7),('RIGHTPADDING',(0,0),(-1,-1),7),('LINEBELOW',(0,0),(-1,0),.6,green),('LINEBELOW',(0,1),(-1,-1),.25,colors.HexColor('#dbe3dc'))]))
        story.append(item)
    people={r['id']:r['email'] for r in report['people']};vaults={r['id']:r['name']+'\n'+r['id'] for r in report['vaults']}
    story.extend([p(report['brand'],small),p('Client access\nProof Pack',title),p(report['client']['name'],heading),p('Snapshot '+report['generated_at'],small),p('Report '+report['id'],small),Spacer(1,12)])
    counts=f"{len(report['access'])} vault grants | {len(report['reported_accounts'])} external-account reports | {len(report['offboarding'])} offboarding runs"
    story.extend([p(counts),p(report['limitations'],small)])
    section('Current vault access','Accepted access and pending invitations are distinct. This does not list external website sessions.')
    table(['Person','Vault','Role / state'],[[people.get(r['person'],r['person']),vaults.get(r['vault'],r['vault']),r['role']+' / '+('accepted' if r['accepted'] else 'invited')] for r in report['access']],[192,192,127])
    section('Reported external accounts','Owner reports and opt-in login-attempt observations are unverified external access.')
    table(['Person','Site / label','Source / state'],[[people.get(r['person'],r['person']),r['domain']+'\n'+r['account_label'],r['source']+' / '+r['state']] for r in report['reported_accounts']],[165,181,165])
    section('Staff account MFA','MFA enrollment in this SentinelOps account only; external-service MFA and enforcement at every sign-in are unknown.')
    table(['Person','Workspace membership','App MFA enrolled'],[[r['email'],r['workspace_role'] or 'Former / unavailable','Yes' if r['app_mfa_enrolled'] else 'No / unavailable'] for r in report['people']],[250,150,111])
    section('Offboarding log','Preview runs do not remove access. Completed server removal does not erase copied credentials; sharing-key rotation and website-password changes are separate.')
    table(['Person / run','Mode / status','Created / updated'],[[people.get(r['person'],r['person'])+'\n'+r['id'],('Preview' if r['dry_run'] else 'Real removal')+' / '+r['status'],r['created_at']+'\n'+r['updated_at']] for r in report['offboarding']],[204,135,172])
    table(['Vault / action','Result / run','Completed at'],[[vaults.get(r['vault'],r['vault'])+'\n'+r['action'],r['status']+' / '+str(r['outcome'] or 'Not recorded')+'\n'+r['workflow'],r['completed_at']] for r in report['steps']],[230,133,148])
    if report['posture_included']:
        section('Device evidence retained at removal','Existing helper observations captured with the first real removal, not a new scan. Missing snapshots do not establish device protection. Current recorded posture is listed separately below.')
        for run in report['offboarding']:
            snapshot=run.get('posture_snapshot')
            story.append(p('Run '+run['id'],small))
            if not snapshot:
                story.append(p('No retained removal-time snapshot.',small));continue
            story.extend([p('Captured '+snapshot['captured_at'],small),p(snapshot['limitations'],small)])
            if snapshot['device_limit_reached']:story.append(p('INCOMPLETE: more than 100 devices were registered.',small))
            if not snapshot['devices']:story.append(p('No paired device evidence was available at removal.',small))
            for device in snapshot['devices']:
                story.append(p(device['platform']+' / '+device['freshness']+' / recorded '+str(device['recorded_at'] or 'never')+(' / connection expired' if device['connection_expired'] else ''),small))
                table(['Check','Recorded state','Reason'],[[r['id'],r['state'],r['reason'] or '-'] for r in device['checks']],[192,147,172])
    section('Scheduled removal rechecks','Pending checks are not verification. These check selected SentinelOps vault access, not external website sessions.')
    table(['Run / interval','State','Due / checked'],[[r['workflow']+'\n'+r['label'],r['status'],datetime.fromtimestamp(r['due'],timezone.utc).isoformat()+'\n'+str(r['checked_at'] or 'Not checked')] for r in report['rechecks']],[192,147,172])
    section('Shared-password debt','State is owner-reported and does not independently establish password rotation or delegated access.')
    table(['Site','Recorded state','Last updated'],[[r['domain'],r['state'],r['updated_at']] for r in report['debt']],[192,147,172])
    section('Handoff sign-off','Device retrieval/wipe and external-access confirmations are human attestations, not independent checks.')
    table(['Kind / record','Status','Sign-off'],[[r['kind']+'\n'+r['id'],r['status']+(' / EVIDENCE CHANGED' if r['evidence_changed_since_signoff'] else ''),str(r['signoff'] or 'Not signed off')] for r in report['handoffs']],[175,124,212])
    section('Selected website / project checks','Client association is explicitly selected by the report owner. Status and finding counts are recorded observations; no raw code, request headers, findings evidence or credentials are exported.')
    table(['System','Last check / state','Recorded counts'],[[r['name'],str(r['at'] or 'Never')+'\n'+r['status'],', '.join(f'{k}: {v}' for k,v in sorted(r['finding_counts'].items())) or 'No recorded findings; not proof of safety'] for r in report['checks']],[192,166,153])
    section('Device posture','Included only when selected. Paired helper self-report; stale, missing and unsupported checks are not healthy-device assertions.')
    if not report['posture_included']:story.append(p('Device posture was not included in this snapshot.',small))
    for device in report['posture']:
        story.extend([p(people.get(device['person'],device['person'])+' / '+device['label']),p('Recorded '+str(device['at'] or 'never')+' | '+device['freshness']+' | '+('connection expired' if device['connection_expired'] else 'connection unexpired'),small)])
        table(['Check','Recorded state','Reason'],[[r['id'],r['state'],r['reason'] or '-'] for r in device['checks']],[192,147,172])
    if report['posture_included'] and not report['posture']:story.append(p('No paired device posture was recorded for the selected client staff.',small))
    section('Audit and integrity','The server checked its full workspace chain at snapshot time. This client-only excerpt is not a complete chain or an independent signature.')
    story.extend([p('Server-reported chain check: '+('valid' if report['audit']['valid'] else 'FAILED - treat evidence as untrusted')),p('Retained workspace head: '+report['audit']['head'],small),p('Snapshot SHA-256: '+report['digest'],small)])
    table(['UTC timestamp','Recorded event','Target'],[[r['at'],r['action'],r['target']] for r in report['audit']['events']],[155,181,175])
    story.append(p('Unsupported glyphs are shown as [U+XXXX] to preserve their identity without unreadable squares. Obtain the JSON snapshot for the original Unicode text.',small))
    def footer(canvas,doc):
        if doc.page>100:raise ValueError('Proof Pack exceeds the 100-page rendering limit.')
        canvas.setFont('ProofSans',7);canvas.setFillColor(muted);canvas.drawString(42,25,'Point-in-time records | '+report['generated_at'][:10]);canvas.drawRightString(A4[0]-42,25,'Page '+str(doc.page))
    doc=SimpleDocTemplate(out,pagesize=A4,leftMargin=42,rightMargin=42,topMargin=38,bottomMargin=42,title='Client access Proof Pack',author=report['brand'],allowSplitting=1)
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    value=out.getvalue()
    if len(value)>5*1024*1024:raise ValueError('Proof Pack PDF exceeds 5 MiB.')
    return value
