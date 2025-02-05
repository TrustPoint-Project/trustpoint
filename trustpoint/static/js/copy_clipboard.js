const iconCopyUrl = "/static/img/icons.svg#icon-copy";
const iconSuccessUrl = "/static/img/icons.svg#icon-success";

function copyToClipboard() {
    const commandElement = document.getElementById("onboarding-command");
    const text = commandElement.innerText.trim();

    navigator.clipboard.writeText(text)
        .then(() => {
            const iconUse = document.querySelector('#copy-button svg use');
            iconUse.setAttribute('xlink:href', iconSuccessUrl);

            setTimeout(() => {
                iconUse.setAttribute('xlink:href', iconCopyUrl);
            }, 2000);
        })
        .catch(err => {
            console.error('Error copying text: ', err);
        });
}

document.addEventListener('DOMContentLoaded', function() {
    const copyBtn = document.getElementById('copy-button');
    if (copyBtn) {
        copyBtn.addEventListener('click', copyToClipboard);
    }
});