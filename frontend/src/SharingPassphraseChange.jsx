export default function SharingPassphraseChange({busy,onChange}) {
  return <details className="spaced"><summary>Change your sharing passphrase</summary>
    <form className="operator-form spaced" onSubmit={event=>{
      event.preventDefault();const form=event.currentTarget,fields=new FormData(form);
      const current=fields.get('current_sharing'),next=fields.get('new_sharing'),confirm=fields.get('confirm_sharing');
      form.reset();onChange(current,next,confirm);
    }}>
      <p>This re-encrypts your existing private sharing keys locally. Shared vault contents, your fingerprint and teammates’ access stay the same. Your shared browser connections across workspaces will be revoked, unfinished shared account actions cancelled, and pending ownership proposals you sent or received cancelled. Pair again afterward.</p>
      <label>Current sharing passphrase<input name="current_sharing" type="password" autoComplete="current-password" minLength={15} maxLength={256} required/></label>
      <label>New sharing passphrase<input name="new_sharing" type="password" autoComplete="new-password" minLength={15} maxLength={256} required/></label>
      <label>Confirm new sharing passphrase<input name="confirm_sharing" type="password" autoComplete="new-password" minLength={15} maxLength={256} required/></label>
      <p className="fine">Existing unlocked clients, downloaded encrypted copies and backups cannot be erased. This does not rotate identity keys or recover a forgotten passphrase. Keep the old passphrase for older encrypted backups.</p>
      <button className="button" disabled={busy}>Change sharing passphrase and lock</button>
    </form>
  </details>;
}
