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
const tableSelectButtons = document.querySelectorAll('.tp-table-select-btn');


checkboxColumn?.addEventListener('change', toggleAllCheckboxes);
if (checkboxColumn) {
    tableSelectButtons.forEach(function(el) {
        el.addEventListener('click', function(event) {
            let url_path = event.target.getAttribute('data-tp-url') + '/';
            console.log(url_path)
            let at_least_one_checked = false;
            checkboxes.forEach(function(el) {
                if (el.checked) {
                    url_path += el.value + '/';
                    at_least_one_checked = true;
                }
            });
            if (at_least_one_checked === true) {
                window.location.href = url_path;
            }
        })
    });
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

// ---------------------------------------- Table Query update ----------------------------------------

function updateQueryParam(event, key, value) {
    event.preventDefault();
    const url = new URL(window.location);
    if (key == 'sort' && value == url.searchParams.get('sort')) {
        value = `-${value}`; // toggle to descending order
    }
    url.searchParams.set(key, value);
    window.location.href = url.toString();
}

// ---------------------------------------- Side nav menu toggling ----------------------------------------

function hideMenu() {
    document.querySelector('.tp-sidenav').classList.remove('sidenav-show');
    document.querySelector('#menu-icon-menu').classList.remove('d-none');
    document.querySelector('#menu-icon-back').classList.add('d-none');
}

function toggleMenu(event) {
    document.querySelector('.tp-sidenav').classList.toggle('sidenav-show');
    document.querySelector('#menu-icon-menu').classList.toggle('d-none');
    document.querySelector('#menu-icon-back').classList.toggle('d-none');
}

function setupMenuToggle() {
    document.querySelector('.menu-icon').addEventListener('click', toggleMenu);
    document.querySelector('.tp-main').addEventListener('click', hideMenu);
}

window.addEventListener('load', function(e) {
    setupMenuToggle();
});

// ---------------------------------------- Side nav submenu collapsing ----------------------------------------

// custom collapse implementation, since the one provided by Bootstrap does not allow preventing navigation

// add onclick event listener to all elements with btn-collapse class
const collapseButtons = document.querySelectorAll('.btn-collapse');
collapseButtons.forEach(function(button) {
    button.addEventListener('click', toggleCollapse);
    if (button.ariaExpanded === "true") {
        setMenuCollapsed(button, false); // to set explicit scroll height for CSS transition
    }
    // if the menu was manually expanded, keep it expanded upon navigation
    if (button.dataset.category && sessionStorage.getItem('tp-menu-expanded-manually-' + button.dataset.category) === 'true') {
        setMenuCollapsed(button, false, false);
    }
});

function setMenuCollapsed(btn, collapse=true, transition=true) {
    const target = btn?.parentElement.parentElement.querySelector('.tp-menu-collapse');
    if (!target) return;

    if (transition) {
        btn.classList.add('collapse-transition');
        target.classList.add('collapse-transition');
    } else {
        btn.classList.remove('collapse-transition');
        target.classList.remove('collapse-transition');
    }

    if (collapse) {
        btn.ariaExpanded = "false";
        target.style.height = '0px';
    } else {
        btn.ariaExpanded = "true";
        if (target.scrollHeight > 0)
            target.style.height = target.scrollHeight + 'px';
        else
            target.style.height = 'auto';
    }

    //target.style.transition = transition ? 'height 0.2s' : 'none';
}

function toggleCollapse(event) {
    // stop propagation to prevent the event from loading the page
    event.preventDefault();

    let collapse = this.ariaExpanded === "true";
    setMenuCollapsed(this, collapse);

    if (this.dataset.category) {
        sessionStorage.setItem('tp-menu-expanded-manually-' + this.dataset.category, !collapse);
    }
}

// ---------------------------------------- Certificate Download Format Options ----------------------------------------

const derSelect = document.querySelector('#id_cert_file_format > option[value=der]');
const certCount = document.querySelector('#cert-count');
const certFileContainerSelect = document.getElementById('id_cert_file_container');
const certChainInclSelect = document.getElementById('id_cert_chain_incl');
const certFileFormatSelect = document.getElementById('id_cert_file_format');

if (derSelect && certCount && certFileContainerSelect && certChainInclSelect && certFileFormatSelect) {
    togglePemSelectDisable()
    certFileContainerSelect.addEventListener('change', togglePemSelectDisable);
    certChainInclSelect.addEventListener('change', togglePemSelectDisable);
    certFileFormatSelect.addEventListener('change', togglePemSelectDisable);
}

function togglePemSelectDisable() {
    if (certChainInclSelect.value === 'chain_incl') {
        derSelect.disabled = true;
    } else derSelect.disabled = !(certCount.innerText !== '1' && certFileContainerSelect.value !== 'single_file');

    if (derSelect.disabled && certFileFormatSelect.value === 'der') {
            certFileFormatSelect.value = 'pem';
    }
}

// ----------------------------------------------- Global Popper Enable ------------------------------------------------

// Air: disabled as we are not currently using popovers and this requires jQuery 
// $(function () {
//   $('[data-toggle="popover"]').popover()
// })