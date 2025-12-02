const API_BASE_URL = 'http://localhost:8080/api/v1';

function escapeHtml(str) {
    return String(str)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

function showAlert(elementId, message, type = 'info') {
    const alertDiv = document.getElementById(elementId);
    alertDiv.innerHTML = `<div class="alert alert-${type}">${message}</div>`;
    setTimeout(() => alertDiv.innerHTML = '', 5000);
}

function setToken(token) {
    if (!token) return;
    localStorage.setItem('token', token);
}

function getAuthHeaders() {
    const token = localStorage.getItem('token');
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
}

function clearAuth() {
    localStorage.removeItem('token');
    localStorage.removeItem('userEmail');
    localStorage.removeItem('userName');
}

function showRegister() {
    document.getElementById('registerScreen').classList.remove('hidden');
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('dashboardScreen').classList.add('hidden');
    document.getElementById('buscarUsuarioScreen').classList.add('hidden');
    document.getElementById('errorScreen').classList.add('hidden');
    document.getElementById('forgotPasswordScreen').classList.add('hidden'); 
    document.getElementById('resetPasswordScreen').classList.add('hidden');
}

function showLogin() {
    document.getElementById('registerScreen').classList.add('hidden');
    document.getElementById('loginScreen').classList.remove('hidden');
    document.getElementById('dashboardScreen').classList.add('hidden');
    document.getElementById('buscarUsuarioScreen').classList.add('hidden');
    document.getElementById('errorScreen').classList.add('hidden');
    document.getElementById('forgotPasswordScreen').classList.add('hidden'); 
    document.getElementById('resetPasswordScreen').classList.add('hidden');
}

function showErrorScreen(message = "O token é inválido ou expirou.") {
    document.getElementById('registerScreen').classList.add('hidden');
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('dashboardScreen').classList.add('hidden');
    document.getElementById('buscarUsuarioScreen').classList.add('hidden');
    document.getElementById('forgotPasswordScreen').classList.add('hidden');
    document.getElementById('resetPasswordScreen').classList.add('hidden');

    const errorScreen = document.getElementById('errorScreen');
    errorScreen.classList.remove('hidden');
    errorScreen.querySelector('.subtitle').textContent = message;
}

function showDashboard(userData = {}) {
    document.getElementById('registerScreen').classList.add('hidden');
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('buscarUsuarioScreen').classList.add('hidden');
    document.getElementById('forgotPasswordScreen').classList.add('hidden');
    document.getElementById('resetPasswordScreen').classList.add('hidden');
    document.getElementById('errorScreen').classList.add('hidden');
    document.getElementById('dashboardScreen').classList.remove('hidden');

    document.getElementById('userName').textContent = userData.nome || localStorage.getItem('userName') || 'N/A';
    document.getElementById('userEmail').textContent = userData.email || localStorage.getItem('userEmail') || 'N/A';
    document.getElementById('userToken').textContent = userData.token || localStorage.getItem('token') || 'N/A';
}

function showBuscarUsuario() {
    document.getElementById('dashboardScreen').classList.add('hidden');
    document.getElementById('buscarUsuarioScreen').classList.remove('hidden');
}

function voltarDashboard() {
    document.getElementById('buscarUsuarioScreen').classList.add('hidden');
    document.getElementById('dashboardScreen').classList.remove('hidden');
}

function showResetPassword() {
    document.querySelectorAll('.screen').forEach(div => div.classList.add('hidden'));
    document.getElementById('resetPasswordScreen').classList.remove('hidden');
}

function showForgotPassword() {
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('registerScreen').classList.add('hidden');
    document.getElementById('dashboardScreen').classList.add('hidden');
    document.getElementById('forgotPasswordScreen').classList.remove('hidden');
    document.getElementById('resetPasswordScreen').classList.add('hidden');
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('linkToLogin').addEventListener('click', (e) => { 
        e.preventDefault(); 
        showLogin(); 
    });
    document.getElementById('linkToRegister').addEventListener('click', (e) => { 
        e.preventDefault(); 
        showRegister(); 
    });

    document.getElementById('googleLoginBtn').addEventListener('click', loginWithGoogle);
    document.getElementById('githubLoginBtn').addEventListener('click', loginWithGithub);

    document.getElementById('btnBuscarUsuario').addEventListener('click', showBuscarUsuario);
    document.getElementById('btnVoltar').addEventListener('click', voltarDashboard);
    document.getElementById('btnLogout').addEventListener('click', logout);
    document.getElementById('btnPesquisar').addEventListener('click', buscarUsuarioPorId);

    document.getElementById('registerForm').addEventListener('submit', handleRegister);
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    document.getElementById('forgotForm').addEventListener('submit', handleForgotPassword);
    document.getElementById('resetPasswordForm').addEventListener('submit', handleResetPassword);

    document.getElementById('forgotPasswordBtn').addEventListener('click', showForgotPassword);
    document.getElementById('backToLoginBtn').addEventListener('click', showLogin);

    const urlParams = new URLSearchParams(window.location.search);
    const resetToken = urlParams.get('resetToken');
    
    if (resetToken) {
        document.getElementById('resetToken').value = resetToken;
        showResetPassword();
        window.history.replaceState({}, document.title, window.location.pathname);
        return; 
    }

    handleInitialAuthFromUrlOrStorage();
});

async function handleRegister(event) {
    event.preventDefault();
    const btn = document.getElementById('registerBtn');
    const originalText = btn.innerHTML;
    try {
        btn.innerHTML = '<span class="loading"></span> Cadastrando...';
        btn.disabled = true;

        const userData = {
            nome: document.getElementById('registerName').value.trim(),
            email: document.getElementById('registerEmail').value.trim(),
            senha: document.getElementById('registerPassword').value
        };

        const res = await fetch(`${API_BASE_URL}/auth/registro`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(userData)
        });

        if (res.ok) {
            showAlert('registerAlert', 'Cadastro realizado com sucesso! Faça login.', 'success');
            setTimeout(() => showLogin(), 1200);
        } else {
            let errMsg = 'Erro ao cadastrar. Tente novamente.';
            try {
                const errJson = await res.json();
                errMsg = errJson.message || JSON.stringify(errJson);
            } catch (e) {
                try { errMsg = await res.text(); } catch (ee) {}
            }
            showAlert('registerAlert', errMsg, 'error');
        }
    } catch (error) {
        showAlert('registerAlert', 'Erro de conexão com o servidor.', 'error');
        console.error('Erro registro:', error);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

async function handleLogin(event) {
    event.preventDefault();
    const btn = document.getElementById('loginBtn');
    const originalText = btn.innerHTML;
    try {
        btn.innerHTML = '<span class="loading"></span> Entrando...';
        btn.disabled = true;

        const credentials = {
            email: document.getElementById('loginEmail').value.trim(),
            senha: document.getElementById('loginPassword').value
        };

        const res = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(credentials)
        });

        if (!res.ok) {
            const contentType = res.headers.get('content-type') || '';
            let errMsg;

            if (contentType.includes('application/json')) {
                const errJson = await res.json();
                errMsg = errJson.message || 'Erro desconhecido.';
            } else {
                errMsg = await res.text();
            }

            if (errMsg.includes("EMAIL NÃO VERIFICADO")) {
                showAlert('loginAlert', '⚠️ Seu email ainda não foi verificado. Verifique antes de fazer login.', 'error');
            } else {
                showAlert('loginAlert', errMsg, 'error');
            }
            return; 
        }

        const data = await res.json();
        if (data.token) {
            setToken(data.token);
            localStorage.setItem('userEmail', credentials.email);
            localStorage.setItem('userName', data.nome || credentials.email);

            showAlert('loginAlert', 'Login realizado com sucesso!', 'success');

            setTimeout(() => {
                showDashboard({
                    nome: data.nome || credentials.email,
                    email: credentials.email,
                    token: data.token
                });
            }, 600);
        } else {
            showAlert('loginAlert', 'Resposta inválida do servidor (sem token).', 'error');
        }
    } catch (error) {
        showAlert('loginAlert', 'Erro de conexão com o servidor.', 'error');
        console.error('Erro login:', error);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

function loginWithGoogle() {
    window.location.href = `${API_BASE_URL.replace('/api/v1', '')}/oauth2/authorization/google`;
}

function loginWithGithub() {
    window.location.href = `${API_BASE_URL.replace('/api/v1', '')}/oauth2/authorization/github`;
}

function logout() {
    clearAuth();
    showLogin();
}

async function handleInitialAuthFromUrlOrStorage() {
    const urlParams = new URLSearchParams(window.location.search);
    const status = urlParams.get('status');
    const tokenFromUrl = urlParams.get('token');
    const tokenLocal = localStorage.getItem('token');

    if (status === 'erro') {
        showErrorScreen("❌ O token de verificação é inválido ou expirou.");
        window.history.replaceState({}, document.title, window.location.pathname);
        return;
    }

    if (status === 'ok') {
        showLogin();
        window.history.replaceState({}, document.title, window.location.pathname);
        return;
    }

    if (tokenFromUrl) {
        setToken(tokenFromUrl);

        try {
            const res = await fetch(`${API_BASE_URL}/usuario/me`, {
                headers: getAuthHeaders()
            });

            if (res.ok) {
                const data = await res.json();
                localStorage.setItem('userName', data.nome || '');
                localStorage.setItem('userEmail', data.email || '');
                showDashboard({ nome: data.nome, email: data.email, token: tokenFromUrl });
                window.history.replaceState({}, document.title, window.location.pathname);
            } else {
                clearAuth();
                showLogin();
            }
        } catch (error) {
            console.error('Erro obtendo perfil com token da URL:', error);
            clearAuth();
            showLogin();
        }
    } else if (tokenLocal) {
        const nome = localStorage.getItem('userName');
        const email = localStorage.getItem('userEmail');
        showDashboard({ nome, email, token: tokenLocal });
    } else {
        showRegister();
    }
}

async function buscarUsuarioPorId() {
    const id = (document.getElementById('buscarId').value || '').trim();
    const resultadoDiv = document.getElementById('resultadoBusca');

    resultadoDiv.innerHTML = '';

    if (!id) {
        resultadoDiv.innerHTML = `<p style="color:red;">Digite um ID válido.</p>`;
        return;
    }

    const token = localStorage.getItem('token');
    if (!token) {
        showAlert('loginAlert', 'Você precisa estar autenticado para realizar essa ação.', 'error');
        showLogin();
        return;
    }

    try {
        const res = await fetch(`${API_BASE_URL}/usuario/${encodeURIComponent(id)}`, {
            method: 'GET',
            headers: getAuthHeaders()
        });

        const data = await parseJsonSafe(res);

        if (res.ok) {
            resultadoDiv.innerHTML = '';
            resultadoDiv.innerHTML = `
                <h2>Resultado</h2>
                <p><strong>ID:</strong> ${data.id}</p>
                <p><strong>Nome:</strong> ${escapeHtml(data.nome || '')}</p>
                <p><strong>Email:</strong> ${escapeHtml(data.email || '')}</p>
            `;
            return;
        }

        if (res.status === 401) {
            showAlert('loginAlert', 'Token inválido ou expirado. Faça login novamente.', 'error');
            logout();
            return;
        }

        if (res.status === 403) {
            resultadoDiv.innerHTML = `
                <p style="color:red;">
                    Acesso negado (403). Você só pode acessar suas próprias informações.<br>
                    Seu ID é: ${data.id || 'desconhecido'}
                </p>`;
            return;
        }

        const errMsg = data.message || `Erro ${res.status}: Não foi possível buscar o usuário.`;
        resultadoDiv.innerHTML = `<p style="color:red;">${escapeHtml(errMsg)}</p>`;

    } catch (error) {
        console.error('Erro na requisição:', error);
        resultadoDiv.innerHTML = `<p style="color:red;">Erro na requisição. Tente novamente.</p>`;
    }
}

async function parseJsonSafe(res) {
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
        return await res.json();
    }
    return {};
}

async function handleForgotPassword(event) {
    event.preventDefault();
    const btn = document.getElementById('sendResetLinkBtn');
    const originalText = btn.innerHTML;
    try {
        btn.innerHTML = '<span class="loading"></span> Enviando...';
        btn.disabled = true;

        const email = document.getElementById('forgotEmail').value.trim();

        const res = await fetch(`${API_BASE_URL}/auth/redefinir-senha`, { 
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({email}) 
        });

        if (res.ok) {
            showAlert('forgotAlert', '📧 Link de recuperação enviado para seu e-mail!', 'success');
        } else {
            const errMsg = await res.text();
            showAlert('forgotAlert', errMsg || 'Erro ao enviar link de recuperação.', 'error');
        }
    } catch (error) {
        showAlert('forgotAlert', 'Erro de conexão com o servidor.', 'error');
        console.error('Erro forgot password:', error);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

async function handleResetPassword(event) {
    event.preventDefault();
    const btn = document.getElementById('resetPasswordBtn');
    const originalText = btn.innerHTML;
    try {
        btn.innerHTML = '<span class="loading"></span> Redefinindo...';
        btn.disabled = true;

        const token = document.getElementById('resetToken').value;
        const newPassword = document.getElementById('newPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        if (newPassword !== confirmPassword) {
            showAlert('resetAlert', '❌ As senhas não coincidem!', 'error');
            return;
        }

        if (newPassword.length < 6) {
            showAlert('resetAlert', '❌ A senha deve ter no mínimo 6 caracteres!', 'error');
            return;
        }

        const res = await fetch(`${API_BASE_URL}/auth/nova-senha`, { 
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                token: token,
                senha: newPassword,
                senhaConfirmacao: confirmPassword
            })
        });

        if (res.ok) {
            showAlert('resetAlert', '✅ Senha redefinida com sucesso! Faça login novamente.', 'success');
            setTimeout(() => showLogin(), 1500);
        } else {
            const errMsg = await res.text();
            showAlert('resetAlert', errMsg || 'Erro ao redefinir senha.', 'error');
        }
    } catch (error) {
        showAlert('resetAlert', 'Erro de conexão com o servidor.', 'error');
        console.error('Erro reset password:', error);
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}