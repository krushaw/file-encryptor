import streamlit as st
import os
import tempfile
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ================== Styling ==================
st.set_page_config(page_title="Secure File Encryptor", page_icon="🔒", layout="wide")

st.markdown(
    """
    <style>
    body {
        background-color: #0e1117;
        color: #fafafa;
    }
    .main-card {
        background: #1a1c23;
        padding: 40px;
        border-radius: 15px;
        box-shadow: 0px 4px 12px rgba(0,0,0,0.5);
        margin: auto;
    }
    .stTextInput>div>div>input {
        border-radius: 8px;
    }
    .stRadio>div {
        flex-direction: row !important;
        justify-content: center;
    }
    .stProgress .st-bo {
        background-color: #262730;
    }
    .success-msg {
        color: #00ff88;
        font-weight: bold;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ================== Crypto ==================
CHUNK_SIZE = 64 * 1024
MAGIC_HEADER = b"ENCRYPTEDv1\n"


def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file(input_path, password, output_path, progress_callback=None):
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    file_size = os.path.getsize(input_path)
    processed = 0

    with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
        f_out.write(salt)
        f_out.write(iv)
        f_out.write(encryptor.update(MAGIC_HEADER))
        while chunk := f_in.read(CHUNK_SIZE):
            f_out.write(encryptor.update(chunk))
            processed += len(chunk)
            if progress_callback:
                progress_callback(processed / file_size)
        f_out.write(encryptor.finalize())


def decrypt_file(input_path, password, output_path, progress_callback=None):
    with open(input_path, "rb") as f_in:
        salt = f_in.read(16)
        iv = f_in.read(16)
        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        header = decryptor.update(f_in.read(len(MAGIC_HEADER)))
        if header != MAGIC_HEADER:
            raise ValueError("Wrong password or corrupted file.")

        file_size = os.path.getsize(input_path) - 16 - 16 - len(MAGIC_HEADER)
        processed = 0

        with open(output_path, "wb") as f_out:
            while chunk := f_in.read(CHUNK_SIZE):
                f_out.write(decryptor.update(chunk))
                processed += len(chunk)
                if progress_callback:
                    progress_callback(processed / file_size)
            f_out.write(decryptor.finalize())


# ================== UI ==================
st.markdown("<div class='main-card'>", unsafe_allow_html=True)

st.title("🔒 Secure File Encryptor (AES-CFB)")
st.write("Easily **Encrypt** or **Decrypt** any file with AES-256 and a password of your choice.")

col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("📂 Upload File")
    uploaded_file = st.file_uploader("Choose a file", type=None)
    if uploaded_file:
        st.info(
            f"**Selected file:** {uploaded_file.name}  "
            f"({round(len(uploaded_file.getvalue()) / 1024 / 1024, 2)} MB)"
        )

with col2:
    st.subheader("⚙️ Settings")

    # use session_state for password
    if "password" not in st.session_state:
        st.session_state.password = ""

    password = st.text_input("🔑 Enter Password", type="password", value=st.session_state.password)

    mode = st.radio("Mode", ["Encrypt", "Decrypt"], horizontal=True)

    if uploaded_file and password:
        if st.button("🚀 Confirm", use_container_width=True):
            with tempfile.NamedTemporaryFile(delete=False) as temp_in:
                temp_in.write(uploaded_file.read())
                temp_in.flush()
                input_path = temp_in.name

            temp_out = tempfile.NamedTemporaryFile(delete=False)
            temp_out.close()
            output_path = temp_out.name

            progress = st.progress(0, text="Processing...")

            try:
                if mode == "Encrypt":
                    encrypt_file(
                        input_path,
                        password,
                        output_path,
                        progress_callback=lambda pct: progress.progress(
                            int(pct * 100), text=f"{int(pct * 100)}%"
                        ),
                    )
                    result_filename = uploaded_file.name + ".enc"
                else:
                    decrypt_file(
                        input_path,
                        password,
                        output_path,
                        progress_callback=lambda pct: progress.progress(
                            int(pct * 100), text=f"{int(pct * 100)}%"
                        ),
                    )
                    result_filename = uploaded_file.name.replace(".enc", "")

                with open(output_path, "rb") as f:
                    st.markdown(
                        "<p class='success-msg'>✅ Done! Your file is ready.</p>",
                        unsafe_allow_html=True,
                    )
                    st.download_button("⬇️ Download File", f, file_name=result_filename)

                # clear password after success
                st.session_state.password = ""

            except ValueError as e:
                st.error(str(e))
            except Exception as e:
                st.error(f"Error: {str(e)}")

st.markdown("</div>", unsafe_allow_html=True)
