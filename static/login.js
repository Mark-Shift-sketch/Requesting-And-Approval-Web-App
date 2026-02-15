function TTP(fieldId, togleId ){
    const field = document.getElementById(fieldId);
    const toggle = document.getElementById(togleId).querySelector("img");

    if (field.type === "password"){
        field.type = "text";
        toggle.src = 'static/hide.png';
        toggle.alt = "hide Password";
    }else{
        field.type = 'password';
        toggle.src = '/static/eye.png';
        toggle.alt = "Show Password"
    }
}