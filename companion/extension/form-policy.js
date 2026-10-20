export function isNewPassword(field, pageUrl = location.href) {
  if (field.type !== 'password' || field.disabled || field.readOnly || field.autocomplete === 'current-password') return false;
  const hint = field.name + ' ' + field.id;
  if (/confirm|repeat|retype/i.test(hint)) return false;
  if (/(new|create|signup|register)/i.test(hint)) return true;
  try { if(/(?:register|signup|sign-up|change-password|reset-password)/i.test(new URL(pageUrl).pathname))return true; } catch { return false; }
  // Some login sites use new-password to suppress browser password managers.
  // Override that hint only for a visible, unambiguous single-password sign-in.
  return field.autocomplete === 'new-password' && !explicitLoginForm(field);
}
function explicitLoginForm(field) {
  const form=field.form;
  if(!form || form.querySelectorAll('input[type="password"]').length!==1)return false;
  const visible=element=>element.getClientRects().length && !element.disabled && !element.readOnly;
  if(![...form.querySelectorAll('input[autocomplete="username"],input[type="email"],input[name="username"],input[name="email"]')].some(visible))return false;
  return [...form.querySelectorAll('button[type="submit"],button:not([type]),input[type="submit"]')].some(button=>visible(button) && /^(?:log[\s-]?in|sign[\s-]?in)$/i.test((button.tagName==='INPUT'?button.value:button.textContent).trim()));
}
export function formOriginAllowed(pageUrl, action) {
  try {
    const url = new URL(pageUrl);
    return url.protocol === 'https:' && (!action || new URL(action, pageUrl).origin === url.origin);
  } catch { return false; }
}
export function setPasswordFields(field, password) {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  const form = field.closest('form');
  const fields = [field, ...[...(form?.querySelectorAll('input[type="password"]') || [])].filter(f => f !== field && /confirm|repeat|retype/i.test(f.name + ' ' + f.id) && !f.disabled && !f.readOnly)];
  for (const input of fields) {
    setter.call(input, password);
    input.dispatchEvent(new Event('input', {bubbles:true}));
    input.dispatchEvent(new Event('change', {bubbles:true}));
  }
}
