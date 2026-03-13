function ztaNotify(message,type="success"){

    const container=document.getElementById("zta-notify-container");

    const note=document.createElement("div");

    note.className="zta-notify zta-"+type;

    note.innerText=message;

    container.appendChild(note);

    setTimeout(()=>{
        note.remove();
    },4000);
}