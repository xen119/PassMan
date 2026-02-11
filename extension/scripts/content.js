function getCandidateInput(selectors) {
  for (const selector of selectors) {
    const element = document.querySelector(selector);
    if (element && element instanceof HTMLInputElement && !element.disabled) {
      return element;
    }
  }
  return null;
}

function fillField(input, value) {
  if (!input || value == null) {
    return false;
  }
  input.focus();
  input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
}

function safeSendMessage(message, callback) {
  if (!chrome.runtime?.sendMessage) {
    return;
  }

  const wrappedCallback = (response) => {
    if (chrome.runtime?.lastError) {
      return;
    }
    callback?.(response);
  };

  try {
    chrome.runtime.sendMessage(message, wrappedCallback);
  } catch (err) {
    // extension context may be invalidated, ignore
  }
}

  safeSendMessage({ type: 'autofill-request', hostname: location.hostname }, (response) => {
  if (!response?.found) {
    return;
  }

  const entry = response.entry;
  const usernameField = getCandidateInput([
    'input[name*=user]',
    'input[name*=email]',
    'input[type=email]',
    'input[name*=login]',
    'input[name*=name]',
    'input[type=text]',
  ]);
  const passwordField = getCandidateInput(['input[type=password]', 'input[name*=pass]']);
  const otpField = getCandidateInput([
    'input[name*=otp]',
    'input[name*=token]',
    'input[name*=code]',
    'input[placeholder*=OTP]',
  ]);

  fillField(usernameField, entry.username);
  fillField(passwordField, entry.password);
  fillField(otpField, entry.otp);

  if (entry.autoSignIn && passwordField) {
    const form = passwordField.closest('form') || passwordField.form;
    if (form instanceof HTMLFormElement) {
      setTimeout(() => {
        if (form.requestSubmit) {
          form.requestSubmit();
        } else {
          form.submit();
        }
      }, 200);
    }
  }
});

function gatherUsername(form) {
  const selectors = [
    'input[name*=user]',
    'input[name*=email]',
    'input[type=email]',
    'input[name*=login]',
    'input[type=text]',
  ];
  for (const selector of selectors) {
    const field = form.querySelector(selector);
    if (field && field instanceof HTMLInputElement && !field.disabled) {
      return field.value.trim();
    }
  }
  return '';
}

function onPasswordSubmit(event) {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  const passwordField = form.querySelector('input[type=password]');
  if (!passwordField || !passwordField.value) {
    return;
  }

  const credential = {
    username: gatherUsername(form),
    password: passwordField.value,
    url: location.href,
    hostname: location.hostname,
    label: document.title,
  };

  safeSendMessage({ type: 'password-detected', credential });
}

document.addEventListener('submit', onPasswordSubmit, true);
