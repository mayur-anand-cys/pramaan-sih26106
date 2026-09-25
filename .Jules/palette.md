## 2026-09-25 - Contextual Tooltips & Guidance in Streamlit SOC Dashboard
**Learning:** Interactive SOC dashboard controls (e.g. sample file toggles, cryptographic verification buttons, PDF downloads) can cause user friction if their exact behavior or output isn't clear prior to interaction.
**Action:** Always provide explicit, accessible `help` parameter strings on Streamlit input triggers (`st.checkbox`, `st.file_uploader`, `st.button`, `st.download_button`) and informative empty-state callouts.
