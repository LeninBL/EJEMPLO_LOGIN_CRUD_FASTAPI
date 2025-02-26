document.getElementById("profile-form").addEventListener("submit", async function(event) {
    event.preventDefault();

    const currentPassword = document.getElementById("current-password").value;
    const newPassword = document.getElementById("new-password").value;
    const confirmPassword = document.getElementById("confirm-password").value;

    const userDetails = {
        current_password: currentPassword,
        new_password: newPassword,
        confirm_password: confirmPassword,
        first_name: document.getElementById("first-name").value,
        last_name: document.getElementById("last-name").value,
        username: document.getElementById("username").value,
        dob: document.getElementById("dob").value,
        location: document.getElementById("location").value,
        bio: document.getElementById("bio").value
    };

    try {
        const response = await fetch("http://127.0.0.1:8000/users/me/update_profile", {
            method: "PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(userDetails),
            credentials: 'include' 
        });

        if (response.ok) {
            alert("Perfil actualizado con éxito.");
            location.reload(); 
        } else {
            const errorData = await response.json();
            console.error("Error:", errorData);
            alert("Hubo un error al actualizar el perfil. Código de estado: " + response.status);
        }
    } catch (error) {
        console.error("Error:", error);
        alert("Hubo un error al actualizar el perfil.");
    }
});