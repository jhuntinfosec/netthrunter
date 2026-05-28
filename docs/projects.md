# Capstone Projects Overview

The core of the **Advanced Infrastructure & Adversary Hunting Curriculum** is engineering. Reading theory is insufficient; to hunt advanced persistent threats you must be able to code, automate, and process large amounts of data.

At the end of each module, you are tasked with completing a capstone project. By the end of this curriculum, you will have a functional, custom-built threat intelligence scanning, enrichment, detection, and reporting engine.

### Reference Library Integration
Each capstone project relies heavily on concepts taught in our provided offline reference library (the `/books` directory in the repository). 

* **Black Hat Python 2E** & **Hacking APIs**: Essential for networking and building the TLS/Certificate active scanners (Modules 1, 2, 4, 6).
* **The Threat Hunter's Query Playbook**: Heavily informs the overlap and clustering logic (Module 3).
* **Data Engineering for Cybersecurity**: Critical for handling massive stealer leak files, graph modeling, and entropy datasets (Modules 5, 7, 10).
* **Art of Cyber Warfare** & **Adversarial Tradecraft**: Inform our proxy analysis and operational security evasion models (Modules 8, 9).
* **Detection engineering and cloud security references**: Support detection packs, SaaS/OAuth, Kubernetes, and KEV correlation (Modules 0x10-0x13).

### Repository Execution
You can find each capstone project in the matching `projects/0xNN_*` directory. It is highly recommended to build all these scripts locally within a Python `venv`.

Happy Hunting.

## Newer Capstone Additions

The curriculum now includes four downstream operationalization projects:

- `projects/0x10_detection_pack/detection_pack_builder.py` turns AIH-C findings into Sigma-like YAML and OCSF-style examples.
- `projects/0x11_saas_identity_hunter/saas_audit_hunter.py` scores OAuth/SaaS audit events and extracts infrastructure pivots.
- `projects/0x12_k8s_mapper/k8s_exposure_mapper.py` scores Kubernetes and registry exposure metadata.
- `projects/0x13_kev_correlator/kev_infra_correlator.py` joins exploited-vulnerability intelligence with exposed-service fingerprints.
