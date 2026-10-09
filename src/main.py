import streamlit as st
from rag_chain import create_vector_db, get_qa_chain


st.set_page_config(page_title="SOC RAG Assistant", page_icon="🛡️")
st.title("🛡️ SOC Incident Response Assistant")
st.caption("Paste a log line and it will be matched against the MITER ATT&CK.")

@st.cache_resource
def load_chain():
    return get_qa_chain()


with st.sidebar:
    if st.button("Rebuild knowledge base"):
        with st.spinner("Creating vector database..."):
            create_vector_db()
        load_chain.clear()
        st.success("Done!")

log_line = st.text_area("Logline:", height=150)


if st.button("Analyze") and log_line:
    chain = load_chain()
    with st.spinner("Analyzing..."):
        response = chain(log_line)

    answer = response["result"]
    
    if answer == "INSUFFICIENT_CONTEXT":
        st.warning(answer)
    else:
        st.markdown(answer)


    with st.expander("Sources from MITRE ATT&CK"):
        for doc in response["source_documents"]:
            technique_id = doc.metadata["source"]
            url = "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/")
            st.markdown(f"- [{technique_id}]({url})")