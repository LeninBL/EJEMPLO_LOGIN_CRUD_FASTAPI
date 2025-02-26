document.getElementById('loginForm').addEventListener('submit', async function(event) {
    event.preventDefault(); // previene que el formulario se envíe de forma tradicional y recargue la página
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    const submitButton = document.querySelector('button[type="submit"]');
    submitButton.disabled = true;

    try {
        const response = await fetch('http://127.0.0.1:8000/token', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
            credentials: 'include'
        });

        if (!response.ok) {
            const result = await response.json();
            document.getElementById('errorMessage').textContent = result.detail || 'Invalid username or password';
            return;
        }

        window.location.href = 'http://127.0.0.1:8000/users/me';
    } catch (error) {
        console.error('Error:', error);
        document.getElementById('errorMessage').textContent = 'Error de conexión';
    } finally {
        submitButton.disabled = false;
    }
});


const togglePassword = document.getElementById("togglePassword");
const password = document.getElementById("password");

togglePassword.addEventListener("click", function () {
    const type = password.type === "password" ? "text" : "password";
    password.type = type;
    

    const icon = togglePassword.querySelector("i");
    icon.classList = type === "password" ? "fas fa-eye-slash":"fas fa-eye"; 
});
     

const sessionExpiredMessage = document.getElementById('sessionExpiredMessage');
const contadorElement = document.getElementById('contador');

if (sessionExpiredMessage && contadorElement) {
    let tiempoRestante = 3; 


    const actualizarContador = () => {
        if (tiempoRestante > 0) {
            document.getElementById("loginForm").querySelectorAll("input, button").forEach(element => {
                element.disabled = true;
            });
            contadorElement.textContent = tiempoRestante;
            tiempoRestante--; 
        } else {
    
            sessionExpiredMessage.style.display = 'none';
            document.cookie = "session_expired=; Max-Age=0; Path=/; Secure; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
            clearInterval(intervalo); 
            window.location.reload();
            document.getElementById("loginForm").querySelectorAll("input, button").forEach(element => {
            element.disabled = false;
            });
        }
    };

    const intervalo = setInterval(actualizarContador, 1000);
}




