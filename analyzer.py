import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib

# 1. NARROW DOWN & SPECIFIC DATA: Load more rows to find enough variety
print("Loading and filtering dataset...")
df_full = pd.read_csv(r'D:\Final Project\auth_logs.csv', nrows=200000)
df_full.columns = df_full.columns.str.strip()

# Narrowing down: Separate Attacks and Benign
attacks = df_full[df_full['Label'] != 'Benign']
benign_pool = df_full[df_full['Label'] == 'Benign']

# ERROR FIX: Check if benign data exists before sampling
if not benign_pool.empty:
    benign = benign_pool.sample(n=min(len(attacks), len(benign_pool), 50000))
    df = pd.concat([attacks, benign]).sample(frac=1)
else:
    print("Warning: No 'Benign' labels found. Using available attack data.")
    df = attacks.copy()

# 2. Basic Cleaning
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# 3. PATTERN MATCHING: Direct flag for common attack ports
suspicious_ports = [22, 23, 445, 3389]
df['Is_Suspicious_Port'] = df['Destination Port'].apply(lambda x: 1 if x in suspicious_ports else 0)

# 4. Feature Selection (Includes the new Direct Flag)
features = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Is_Suspicious_Port']
X = df[features]
y = df['Label']

# 5. Encoding & Training
le = LabelEncoder()
y = le.fit_transform(y)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# 6. Save Assets
joblib.dump(model, 'siem_model.pkl')
joblib.dump(le, 'label_encoder.pkl')
df.head(20000).to_csv('siem_sample_data.csv', index=False)

print(f"Model trained and assets saved!")