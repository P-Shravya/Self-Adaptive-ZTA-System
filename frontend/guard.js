async function ztaGuard(resourceApiPath, options) {
  options = options || {};
  const token = localStorage.getItem("access_token");

  if (!token) {
    // Not logged in at all
    if (options.redirectOnNoToken !== false) {
      window.location.href = "login.html";
    }
    return null;
  }

  const res = await fetch(resourceApiPath, {
    method: "GET",
    headers: {
      "Authorization": "Bearer " + token
    }
  });

  // Allowed
  if (res.ok) {
    try {
      return await res.json();
    } catch {
      return {};
    }
  }

  // Step-up required or access denied
  let body = null;
  try {
    body = await res.json();
  } catch {
    // ignore
  }

  const detail = body && body.detail ? body.detail : null;

  // Step-up responses are returned via HTTPException(detail={...})
  if (detail && typeof detail === "object" && detail.status) {
    // Remember where the user was going
    localStorage.setItem("post_auth_redirect", window.location.pathname.split("/").pop());

    if (detail.user_id != null) {
      localStorage.setItem("mfa_user", detail.user_id);
    }
    if (detail.risk_score != null) {
      localStorage.setItem("login_risk_score", detail.risk_score);
    }
    if (detail.pending_mfa_token) {
      localStorage.setItem("pending_mfa_token", detail.pending_mfa_token);
    }

    if (detail.status === "mfa_setup_required") {
      // UX requirement: land on the OTP page first, but show the setup CTA
      // so the user can switch to QR setup without losing the step-up flow.
      localStorage.setItem("mfa_setup_required", "1");
      if (typeof ztaNotify === "function") {
        ztaNotify("You haven't setup mfa please set up mfa.", "warning");
      }
      window.location.href = "mfa.html";
      return null;
    }

    if (detail.status === "mfa_required") {
      if (typeof ztaNotify === "function") ztaNotify("Risk detected. MFA OTP verification required.", "warning");
      window.location.href = "mfa.html";
      return null;
    }

    if (detail.status === "strong_mfa_required") {
      if (typeof ztaNotify === "function") ztaNotify("High risk detected. WebAuthn verification required.", "warning");
      window.location.href = "webauthn.html";
      return null;
    }

    if (detail.status === "manager_approval_required") {
      if (typeof ztaNotify === "function") ztaNotify("Critical risk detected. Manager approval required.", "error");
      window.location.href = "approval_wait.html";
      return null;
    }
  }

  // Regular RBAC deny or block
  if (res.status === 403) {
    if (typeof ztaNotify === "function") ztaNotify("Access denied for your role.", "error");
    if (options.redirectOnForbidden) {
      window.location.href = options.redirectOnForbidden;
    }
    return null;
  }

  // Token expired/invalid
  if (res.status === 401) {
    localStorage.removeItem("access_token");
    if (options.redirectOnUnauthorized !== false) {
      window.location.href = "login.html";
    }
    return null;
  }

  return null;
}

