const DHCP = document.getElementById('id_dhcp');
window.onload = function () {
    dhcpState()
}
if (DHCP) {
    DHCP.addEventListener('change', dhcpState);
}

//Disable the input fields if dhcp is checked
function dhcpState() {
    if ( ! DHCP )
        return;

    if ( DHCP.checked ) {
        element = document.getElementById("id_static_ip_address");
        element.required=false;
        element.disabled=true;

        element = document.getElementById("id_gateway");
        element.required=false;
        element.disabled=true;

        element = document.getElementById("id_netmask");
        element.required=false;
        element.disabled=true;
    } 
    else {
        element = document.getElementById("id_static_ip_address");
        element.required=true;
        element.disabled=false;

        element = document.getElementById("id_gateway");
        element.required=true;
        element.disabled=false;

        element = document.getElementById("id_netmask");
        element.required=true;
        element.disabled=false;
    }

}

// ----- Security settings -----

function detectSettingsMismatch() {
    // tests if the set advanced security settings are lower than the defaults of the set security level
    if (!document.querySelector('#security_configuration')) return; // not in security settings
    let sl = document.querySelector('input[name="security_mode"]:checked').value;
    sl -= 1; // 0-based index, 0 = basic, 1 = medium, 2 = high
    if (sl < 0 || sl > 2) return; // invalid security level
    for (el of document.querySelectorAll('#security_configuration input')) {
        if (!el.dataset?.slDefaults) continue;
        arr = JSON.parse(el.dataset.slDefaults);
        slDefault = arr[sl];
        value = el.value;
        if (el.type === 'checkbox') {
            value = el.checked ? 1 : 0;
        }
        if (value > slDefault && el.dataset.moreSecure === 'false' ||
            value < slDefault && el.dataset.moreSecure === 'true') {
            el.classList.add('mismatch');
            el.dataset.target = slDefault;
        } else
            el.classList.remove('mismatch');
    }
    renderMismatchWarning();
}

function renderMismatchWarning() {
    let mismatches = document.querySelectorAll('#security_configuration .mismatch');
    let warning = document.querySelector('#mismatch_warning');
    if (mismatches.length > 0) {
        warning.style.display = 'flex';
        text = ngettext(
            'An advanced security setting is less secure than the selected security level.',
            'Some advanced security settings are less secure than the selected security level.', mismatches.length);
        text += '<ul>'
        for (el of mismatches) {
            labeltext = document.querySelector('label[for="' + el.id + '"]')?.innerText;
            more = el.dataset.moreSecure === 'true' ? gettext('at least ') : gettext('at most ');
            value = el.value;
            target = el.dataset.target;
            if (el.type === 'checkbox') {
                more = "";
                target = el.dataset.target == 1 ? gettext('enabled') : gettext('disabled');
                value = el.checked ? gettext('enabled') : gettext('disabled');
            }
            format = gettext("is %(is)s, but should be %(leastormost)s%(target)s");
            guide = interpolate(format, {is: value, leastormost: more, target: target}, true);
            text += '<li>' + labeltext + ' (' + guide + ')</li>';
        }
        text += '</ul>'	
        text += ngettext(
            'It is recommended to change this setting to meet the desired security level.',
            'It is recommended to change these settings to meet the desired security level.', mismatches.length);
        text += '<br><button class="btn btn-primary float-end" type="button" onclick="changeMismatchedSettings()">'
        text += ngettext('Change', 'Change all', mismatches.length);
        text += '</button>';
        document.querySelector('#mismatch_warning_text').innerHTML = text;
    } else {
        warning.style.display = 'none';
    }
}

// Add event listeners security settings form inputs
for (el of document.querySelectorAll('#security_configuration input')) {
    el.addEventListener('change', detectSettingsMismatch);
}

function changeMismatchedSettings() {
    let mismatches = document.querySelectorAll('#security_configuration .mismatch');
    for (el of mismatches) {
        if (el.type === 'checkbox') {
            el.checked = el.dataset.target == 1;
        } else {
            el.value = el.dataset.target
        }
    }
    detectSettingsMismatch();
}

detectSettingsMismatch();