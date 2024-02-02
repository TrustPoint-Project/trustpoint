const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))

// ---------------------------------------- Add certificate Authorities ----------------------------------------

const localIssuingCaOptions = document.getElementById('tp-form-local-issuing-ca');
const localIssuingCaRadio = document.getElementById('local-issuing-ca-radio');
const localIssuingCaImportFilesRadio = document.getElementById('local-issuing-ca-import-files');
const localIssuingCaRequestRadio = document.getElementById('local-issuing-ca-request');
if (localIssuingCaOptions != null) {
    localIssuingCaRadio.addEventListener('change', certAuthRadioFormChange);
}

const remoteIssuingCaOptions = document.getElementById('tp-form-remote-issuing-ca');
const remoteIssuingCaRadio = document.getElementById('remote-issuing-ca-radio');
const remoteIssuingCaEstRadio = document.getElementById('remote-issuing-ca-est');
const remoteIssuingCaCmpRadio = document.getElementById('remote-issuing-ca-cmp');
if (remoteIssuingCaRadio != null) {
    remoteIssuingCaRadio.addEventListener('change', certAuthRadioFormChange);
}

function certAuthRadioFormChange() {
    if (localIssuingCaRadio.checked) {
        localIssuingCaOptions.hidden = false;
        remoteIssuingCaOptions.hidden = true;

        localIssuingCaImportFilesRadio.checked = true;
        localIssuingCaRequestRadio.checked = false;

    } else if (remoteIssuingCaRadio.checked) {
        localIssuingCaOptions.hidden = true;
        remoteIssuingCaOptions.hidden = false;

        remoteIssuingCaEstRadio.checked = true;
        remoteIssuingCaCmpRadio.checked = false;
    }
}

const modal = document.getElementById('addCaModal');
if (modal != null) {
    modal.addEventListener('hidden.bs.modal', resetIssuingCaRadios);
}

function resetIssuingCaRadios() {

    localIssuingCaOptions.hidden = true;
    localIssuingCaRadio.checked = false;
    localIssuingCaImportFilesRadio.checked = true;
    localIssuingCaRequestRadio.checked = false;

    remoteIssuingCaOptions.hidden = false;
    remoteIssuingCaRadio.checked = true;
    remoteIssuingCaEstRadio.checked = true;
    remoteIssuingCaCmpRadio.checked = false;
}

function redirectAddIssuingCa() {
    if (localIssuingCaRadio.checked) {
        window.location.href = document.querySelector('input[name="local-issuing-ca"]:checked').value;
    } else if (remoteIssuingCaRadio.checked) {
        window.location.href = document.querySelector('input[name="remote-issuing-ca"]:checked').value;
    }
}

const p12FileForm = document.getElementById('p12-file-form');
const p12FileRadio = document.getElementById('p12-file-radio');
if (p12FileRadio != null) {
    p12FileRadio.addEventListener('change', chooseFileFormatForm);
}

const pemFileForm = document.getElementById('pem-file-form');
const pemFileRadio = document.getElementById('pem-file-radio');
if (pemFileRadio != null) {
    pemFileRadio.addEventListener('change', chooseFileFormatForm);
}

function chooseFileFormatForm() {
    if (p12FileRadio.checked) {
        p12FileForm.hidden = false;
        pemFileForm.hidden = true;
    } else if (pemFileRadio.checked) {
        p12FileForm.hidden = true;
        pemFileForm.hidden = false;
    }
}
