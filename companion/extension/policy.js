export function serviceOrigin(value) {
  const url = new URL(value);
  if (
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash ||
    !(
      url.protocol === "https:" ||
      (url.protocol === "http:" &&
        ["127.0.0.1", "localhost"].includes(url.hostname))
    )
  )
    throw new Error(
      "Use an HTTPS app origin or local loopback origin, without a path.",
    );
  return url.origin;
}
export function mayFill(entryOrigin, pageUrl, formAction) {
  try {
    const page = new URL(pageUrl);
    return (
      page.protocol === "https:" &&
      page.origin === entryOrigin &&
      (!formAction || new URL(formAction, pageUrl).origin === page.origin)
    );
  } catch {
    return false;
  }
}
