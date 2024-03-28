const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl))

// ---------------------------------------- Add certificate Authorities ----------------------------------------

const localIssuingCaOptions = document.getElementById('tp-form-local-issuing-ca');
const localIssuingCaRadio = document.getElementById('local-issuing-ca-radio');
const localIssuingCaImportFilesRadio = document.getElementById('local-issuing-ca-import-files');
const localIssuingCaRequestRadio = document.getElementById('local-issuing-ca-request');
if (localIssuingCaOptions) {
    localIssuingCaRadio.addEventListener('change', certAuthRadioFormChange);
}

const remoteIssuingCaOptions = document.getElementById('tp-form-remote-issuing-ca');
const remoteIssuingCaRadio = document.getElementById('remote-issuing-ca-radio');
const remoteIssuingCaEstRadio = document.getElementById('remote-issuing-ca-est');
const remoteIssuingCaCmpRadio = document.getElementById('remote-issuing-ca-cmp');
if (remoteIssuingCaRadio) {
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
if (modal) {
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
if (p12FileRadio) {
    p12FileRadio.addEventListener('change', chooseFileFormatForm);
}

const pemFileForm = document.getElementById('pem-file-form');
const pemFileRadio = document.getElementById('pem-file-radio');
if (pemFileRadio) {
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
// ---------------------------------------- Table Checkbox Column ----------------------------------------

const checkboxColumn = document.querySelector('#checkbox-column > input');
const checkboxes = document.querySelectorAll('.row_checkbox > input');
const deleteSelectedBtn = document.getElementById('tp-table-delete-selected');

if (checkboxColumn && deleteSelectedBtn) {
    checkboxColumn.addEventListener('change', toggleAllCheckboxes);
    deleteSelectedBtn.addEventListener('click', deleteSelected);
}

function toggleAllCheckboxes() {
    if (checkboxColumn.checked) {
        checkboxes.forEach(function(el) {
            el.checked = true;
        });
    } else {
        checkboxes.forEach(function(el) {
            el.checked = false;
        });
    }
}

function deleteSelected() {
    let url_path = 'delete/'
    let at_least_one_checked = false;
    checkboxes.forEach(function(el) {
        if (el.checked) {
            url_path += el.value + '/'
            at_least_one_checked = true;
        }
    });
    if (at_least_one_checked === true) {
        window.location.href = url_path;
    }
}

// ---------------------------------------- Side nav menu collapsing ----------------------------------------

// add onclick event listener to all elements with btn-collapse class
const collapseButtons = document.querySelectorAll('.btn-collapse');
collapseButtons.forEach(function(button) {
    button.addEventListener('click', toggleCollapse);
});

function toggleCollapse(event) {
    // target is first element with class collapse in parent element
    console.log(this);
    const target = this.parentElement.parentElement.querySelector('.tp-menu-collapse');
    console.log(target);

    if (this.ariaExpanded == "true") {
        this.ariaExpanded = "false";
        target.style.height = '0px';
    } else {
        this.ariaExpanded = "true";
        target.style.height = target.scrollHeight + 'px';
    }
    //this.ariaExpanded = (this.ariaExpanded == "true") ? "false" : "true";

    //target.classList.toggle('show');

    // stop propagation to prevent the event from bubbling up the DOM tree
    event.preventDefault();
}