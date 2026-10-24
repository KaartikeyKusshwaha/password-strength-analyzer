import { validOrigin } from './vault-crypto';
import {isArchived} from './entry-history';

export function accountHealth(entries, check) {
  const logins = entries.filter(e => e.type === 'login' && !isArchived(e));
  const counts = new Map();
  for (const entry of logins) counts.set(entry.password, (counts.get(entry.password) || 0) + 1);
  return logins.map(entry => ({id:entry.id, weak:entry.password.length <= 128 && check(entry.password).score < 3, reused:counts.get(entry.password) > 1, assessed:entry.password.length <= 128}));
}
export function changePasswordUrl(origin) {
  return validOrigin(origin) + '/.well-known/change-password';
}
