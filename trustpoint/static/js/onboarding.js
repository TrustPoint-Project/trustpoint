function startPollingOnboardingState(urlExt, iconUrl) {
  // call getOnboardingState periodically
  setInterval(function() {getOnboardingState(urlExt, iconUrl)} , 2400);
  getOnboardingState(urlExt, iconUrl);
}

// Onboarding states, see onboarding/models.py
const
CONNECTION_ERROR = -3,
NO_SUCH_PROCESS = -2,
FAILED = -1,
STARTED = 0,
HMAC_GENERATED = 1,
TRUST_STORE_SENT = 2,
CSR_RECEIVED = 3,
DEVICE_VALIDATED = 4,
LDEVID_SENT = 5,
COMPLETED = 6 // aka cert chain sent

function getOnboardingState(urlExt, iconUrl) {
  fetch('/onboarding/api/state/'+ urlExt)
    .then(response => response.json())
    .then(data => {
      let val = parseInt(data);
      if (Number.isInteger(val)) setOnboardingStateUI(val, iconUrl);
    }
  ).catch((error) => {
    setOnboardingStateUI(CONNECTION_ERROR, iconUrl);
  })
}

function setOnboardingStateUI(state, iconUrl) {
  let type = 'info';
  let message = '';
  let icon = 'info-circle';
  let extraClasses = '';
  let navBack = false;
  switch (state) {
    case STARTED:
      type = 'info';
      message = 'Generating secrets...';
      icon = 'clock';
      extraClasses = 'breathing-anim';
      break;
    case HMAC_GENERATED:
      type = 'info';
      message = 'Waiting for client to connect...';
      icon = 'clock';
      extraClasses = 'breathing-anim';
      break;
    case TRUST_STORE_SENT:
      type = 'info';
      message = '<strong>Step 1/3</strong> Sent trust store to client. Waiting for CSR...';
      icon = 'clock';
      extraClasses = 'breathing-anim';
      break;
    case CSR_RECEIVED:
      type = 'info';
      message = 'CSR received';
      icon = 'clock';
      break;
    case DEVICE_VALIDATED:
      type = 'info';
      message = '<strong>Step 2/3</strong> Device validated. Signing certificate...';
      icon = 'clock';
      extraClasses = 'breathing-anim';
      break;
    case LDEVID_SENT:
      type = 'info';
      message = '<strong>Step 3/3</strong> Sent signed certificate to client. Waiting for certificate chain request...';
      icon = 'clock';
      extraClasses = 'breathing-anim';
      break;
    case COMPLETED:
      type = 'success';
      message = 'Onboarding completed successfully. Redirecting...';
      icon = 'success';
      navBack = true;
      break;
    case FAILED:
      type = 'danger';
      message = 'Error: Something went wrong during the onboarding process.';
      icon = 'error';
      navBack = true;
      break;
    case NO_SUCH_PROCESS:
      type = 'danger';
      message = 'Error: Server did not find the onboarding process. Please reload the page.';
      icon = 'error';
      window.location.reload();
      break;
    default:
      type = 'warning';
      message = 'Could not get onboarding state from server';
      icon = 'warning';
      break;
  }

  if (navBack) { window.location.href = parentUrl; }

  var el = document.querySelector('#onboarding-state');
  el.className = `alert alert-${type} d-flex align-items-center mt-3 ${extraClasses}`;

  el.innerHTML =
    `<svg class="bi flex-shrink-0 me-2" width="20" height="20" fill="currentColor" role="img" aria-label="State: "><use xlink:href="${iconUrl}#icon-${icon}"/></svg>
    <div>${message}</div>`;
}

if (url) startPollingOnboardingState(url, icons);