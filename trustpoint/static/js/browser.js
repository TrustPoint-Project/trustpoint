document.addEventListener('DOMContentLoaded', function() {
    const copyButton = document.getElementById('copy-button');
    const otpValue = document.getElementById('otp-value');

    if (copyButton && otpValue) {
        copyButton.addEventListener('click', function() {
            const otpText = otpValue.textContent || otpValue.innerText;
            
            navigator.clipboard.writeText(otpText).then(function() {
                copyButton.textContent = 'Copied';

                copyButton.classList.remove('btn-secondary');
                copyButton.classList.add('btn-success');

                setTimeout(function() {
                    copyButton.textContent = 'Copy';
                    copyButton.classList.remove('btn-success');
                    copyButton.classList.add('btn-secondary');
                }, 2000);
            }).catch(function(error) {
                console.error('Could not copy OTP: ', error);
            });
        });
    }
});
