# phishing_detector

## Overview

phishing_detector is a Machine Learning-based phishing website detection system that analyzes URLs and predicts whether a website is legitimate or phishing. The project uses URL feature extraction techniques and a Random Forest classifier to identify malicious websites and help protect users from phishing attacks.

---

## Tech Stack Used

### Frontend
- HTML
- CSS
- JavaScript

### Backend
- Python
- FastAPI

### Machine Learning
- Scikit-learn
- Pandas
- NumPy
- Random Forest Classifier

### Browser Extension
- Chrome Extension API
- Manifest V3

### Version Control
- Git
- GitHub

---

## Workflow

1. User enters a URL through the web interface or Chrome Extension.
2. The URL is sent to the FastAPI backend.
3. The backend extracts phishing-related features from the URL.
4. Extracted features are converted into numerical values.
5. The Random Forest model analyzes the features.
6. The model predicts whether the URL is Legitimate or Phishing.
7. A confidence score and risk level are generated.
8. The result is returned to the frontend or Chrome Extension.
9. The user receives a warning if the website is identified as phishing.

---

## How to Run the Project

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-username/phishing_detector.git
cd phishing_detector
```

### Step 2: Create a Virtual Environment

#### Linux/macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

#### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Start the Backend Server

```bash
uvicorn app:app --reload
```

or

```bash
python app.py
```

### Step 5: Open the Frontend

Open the HTML frontend file in your browser.

```text
phishing_detector.html
```

### Step 6: Load the Chrome Extension (Optional)

1. Open Chrome.
2. Navigate to:

```text
chrome://extensions
```

3. Enable **Developer Mode**.
4. Click **Load Unpacked**.
5. Select the extension folder.
6. Ensure the FastAPI backend is running.
7. Browse websites and receive phishing detection alerts in real time.

---

## Output

The system returns:

- Prediction (Legitimate / Phishing)
- Confidence Score
- Risk Level (Low / Medium / High)

---

## Future Enhancements

- WHOIS Analysis
- SSL Certificate Validation
- Threat Intelligence Integration
- Deep Learning Models
- Real-time Blacklist Checking
