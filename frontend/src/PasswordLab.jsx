import { useMemo, useRef, useState } from "react";
import { LockKeyhole, ShieldCheck, RefreshCw } from "lucide-react";
import { ZxcvbnFactory } from "@zxcvbn-ts/core";
import * as common from "@zxcvbn-ts/language-common";
import * as en from "@zxcvbn-ts/language-en";
import { generatePassword, checkBreach } from "./lab";

const estimator = new ZxcvbnFactory({
  translations: en.translations,
  graphs: common.adjacencyGraphs,
  dictionary: { ...common.dictionary, ...en.dictionary },
});
const labels = [
  "Very guessable",
  "Guessable",
  "Somewhat guessable",
  "Less guessable",
  "Harder to guess",
];
export default function PasswordLab() {
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [breach, setBreach] = useState("Not checked");
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  const result = useMemo(
    () => (password ? estimator.check(password) : null),
    [password],
  );
  function change(value) {
    generation.current++;
    setPassword(value);
    setBreach("Not checked");
    setBusy(false);
  }
  async function check() {
    const version = generation.current;
    setBusy(true);
    try {
      const count = await checkBreach(password);
      if (version === generation.current)
        setBreach(
          count
            ? `Found ${count.toLocaleString()} times in the breach corpus. Change this password wherever used.`
            : "No match in this lookup. This does not establish that the password or account is safe.",
        );
    } catch (error) {
      if (version === generation.current) setBreach(error.message);
    } finally {
      if (version === generation.current) setBusy(false);
    }
  }
  return (
    <div className="two-col">
      <section className="panel">
        <div className="panel-heading">
          <LockKeyhole size={20} />
          <h2>Private password lab</h2>
          <span className="badge green">Local computation</span>
        </div>
        <p className="muted">
          Strength analysis stays in this browser tab. No password history,
          analytics or AI requests.
        </p>
        <label>
          Password to evaluate
          <input
            aria-label="Password to evaluate"
            autoComplete="off"
            type={show ? "text" : "password"}
            value={password}
            maxLength={128}
            onChange={(e) => change(e.target.value)}
          />
        </label>
        <div className="inline">
          <label className="check">
            <input
              type="checkbox"
              checked={show}
              onChange={(e) => setShow(e.target.checked)}
            />
            Show password
          </label>
          <button
            className="button secondary"
            onClick={() => change(generatePassword())}
          >
            <RefreshCw size={15} />
            Generate 24 characters
          </button>
        </div>
        <div className={"strength strength-" + (result?.score ?? 0)}>
          {[0, 1, 2, 3, 4].map((n) => (
            <i
              key={n}
              className={result && n <= result.score ? "filled" : ""}
            />
          ))}
        </div>
        <h2>{result ? labels[result.score] : "Enter a password to begin"}</h2>
        {result && (
          <>
            <p>
              Approx. 10<sup>{result.guessesLog10.toFixed(1)}</sup> guesses
              under the estimator’s pattern model.
            </p>
            <p className="muted">{result.feedback.warning}</p>
            <ul>
              {result.feedback.suggestions.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ul>
          </>
        )}
        <p className="fine">
          An estimate of guessability, not a time-to-compromise prediction.
          English-centric dictionaries can miss names and other languages.
          Maximum 128 characters; never silently truncated.
        </p>
      </section>
      <section className="panel">
        <div className="panel-heading">
          <ShieldCheck size={20} />
          <h2>Compromised password check</h2>
        </div>
        <p>
          Optional lookup against Have I Been Pwned’s Pwned Passwords service.
        </p>
        <div className="privacy-flow">
          <span>Hash locally</span>
          <b>→</b>
          <span>Send 5 hex characters</span>
          <b>→</b>
          <span>Compare locally</span>
        </div>
        <p className="muted">
          Only a SHA-1 prefix goes to HIBP. Your full password and full hash
          stay here. The service still sees your IP and the prefix. Padded
          responses are requested.
        </p>
        <button className="button" disabled={!password || busy} onClick={check}>
          {busy ? "Checking…" : "Check breach corpus"}
        </button>
        <div className="notice" role="status">
          {breach}
        </div>
        <p className="fine">
          Never submit someone else’s password. Prefer unique generated
          passwords, a password manager and passkeys or MFA. Leaving this page
          clears the form.
        </p>
      </section>
    </div>
  );
}
