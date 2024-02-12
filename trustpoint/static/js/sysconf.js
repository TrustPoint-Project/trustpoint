const DHCP = document.getElementById('id_dhcp');
window.onload = function () {
    dhcpState()
}
if (DHCP) {
    DHCP.addEventListener('change', dhcpState);
}

//Disable the input fields if dhc is checked
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