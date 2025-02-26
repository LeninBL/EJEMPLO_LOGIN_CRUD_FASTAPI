function createUser() {
    const user = {
        username: document.getElementById('username').value,
        hashed_password: document.getElementById('new-password').value
    };

    const userDetails = {
        first_name: document.getElementById('first-name').value,
        last_name: document.getElementById('last-name').value,
        dob: document.getElementById('new-dob').value,
        location: document.getElementById('location').value,
        bio: document.getElementById('bio').value
    };

    fetch('http://127.0.0.1:8000/users/me/create', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ user, user_details: userDetails }),
    })
    .then(response => response.json())
    .then(data => {
        alert('Usuario creado exitosamente');
        console.log(data);
    })
    .catch((error) => {
        console.error('Error:', error);
    });
}


function readUser() {
    const userId = document.getElementById('id-user').value;

    fetch(`http://127.0.0.1:8000/users/me/${userId}`, {
        method: 'GET',
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('first-name').value = data.first_name;
        document.getElementById('last-name').value = data.last_name;
        document.getElementById('new-dob').value = data.dob;
        document.getElementById('location').value = data.location;
        document.getElementById('bio').value = data.bio;
    })
    .catch((error) => {
        console.error('Error:', error);
    });
}


function updateUser() {
    const userId = document.getElementById('id-user').value;

    const userUpdate = {
        username: document.getElementById('username').value,
        first_name: document.getElementById('first-name').value,
        last_name: document.getElementById('last-name').value,
        dob: document.getElementById('new-dob').value,
        location: document.getElementById('location').value,
        bio: document.getElementById('bio').value,
        current_password: document.getElementById('new-password').value,
        new_password: document.getElementById('new-password').value, 
    };

    fetch(`http://127.0.0.1:8000/users/me/${userId}`, {
        method: 'PUT',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(userUpdate),
    })
    .then(response => response.json())
    .then(data => {
        alert('Usuario actualizado');
        console.log(data);
    })
    .catch((error) => {
        console.error('Error:', error);
    });
}


function deleteUser() {
    const userId = document.getElementById('id-user').value;

    fetch(`http://127.0.0.1:8000/users/me/${userId}`, {
        method: 'DELETE',
    })
    .then(response => response.json())
    .then(data => {
        alert('Usuario eliminado');
        console.log(data);
    })
    .catch((error) => {
        console.error('Error:', error);
    });
}
