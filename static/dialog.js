document.getElementById("openDialog").addEventListener("click", async () => {
    event.preventDefault();
    // Show the dialog and overlay
    document.getElementById("dialog").style.display = "block";
    document.getElementById("overlay").style.display = "block";
});

document.getElementById("closeDialog").addEventListener("click", () => {
    // Hide the dialog and overlay
    document.getElementById("dialog").style.display = "none";
    document.getElementById("overlay").style.display = "none";
});

