import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64
import random

# Utility function to save plot as base64 string
def fig_to_base64():
    buffer = io.BytesIO()
    plt.savefig(buffer, format="png", bbox_inches="tight")
    buffer.seek(0)
    img_base64 = base64.b64encode(buffer.getvalue()).decode()
    plt.close()
    return img_base64

# Generate a list of n random hex colors
def random_palette(n):
    colors = []
    for _ in range(n):
        colors.append("#"+"".join(random.choices("0123456789ABCDEF", k=6)))
    return colors

###
### PLOT FORM A
###

# 1️⃣ Count of Applications by Risk Rating
def plot_risk_rating_distribution_a(df):
    plt.figure(figsize=(6,4))
    categories = df['risk_rating'].nunique()
    sns.countplot(x="risk_rating", data=df, palette=random_palette(categories), width=0.6)
    plt.title("Applications by Risk Rating")
    return fig_to_base64()

# 2️⃣ Review Recommendations Breakdown
def plot_review_recommendations_a(df):
    plt.figure(figsize=(6,4))
    categories = df['review_recommendation'].nunique()
    sns.countplot(x="review_recommendation", data=df, palette=random_palette(categories), width=0.6)
    plt.title("Review Recommendations")
    plt.xticks(rotation=45)
    return fig_to_base64()

# 3️⃣ Supervisor Recommendations Breakdown
def plot_supervisor_recommendations_a(df):
    plt.figure(figsize=(6,4))
    categories = df['supervisor_recommendation'].nunique()
    sns.countplot(x="supervisor_recommendation", data=df, palette=random_palette(categories), width=0.6)
    plt.title("Supervisor Recommendations")
    plt.xticks(rotation=45)
    return fig_to_base64()

# 4️⃣ Number of Applications per REC Member
def plot_rec_member_distribution_a(df):
    plt.figure(figsize=(6,4))
    categories = df['rec_full_name'].nunique()
    sns.countplot(y="rec_full_name", data=df, palette=random_palette(categories), width=0.6)
    plt.title("Applications Reviewed by Each REC Member")
    return fig_to_base64()

# 5️⃣ Certificate Issued vs Not Issued
def plot_certificate_status_a(df):
    plt.figure(figsize=(6,4))
    categories = df['certificate_issued'].nunique()
    sns.countplot(x="certificate_issued", data=df, palette=random_palette(categories), width=0.6)
    plt.title("Certificate Issuance Status")
    return fig_to_base64()

# 6️⃣ Applications Submitted Over Time
def plot_submissions_over_time_a(df):
    df['submitted_at'] = pd.to_datetime(df['submitted_at'], errors='coerce')
    plt.figure(figsize=(8,4))
    df.groupby(df['submitted_at'].dt.date).size().plot(kind='bar', color=random_palette(df['submitted_at'].dt.date.nunique()), width=0.6)
    plt.title("Submissions Over Time")
    plt.xlabel("Date")
    plt.ylabel("Number of Submissions")
    return fig_to_base64()

# 7️⃣ Review Recommendation by Risk Rating (stacked bar)
def plot_review_by_risk_rating_a(df):
    plt.figure(figsize=(8,4))
    review_risk = pd.crosstab(df['risk_rating'], df['review_recommendation'])
    colors = random_palette(review_risk.shape[1])
    review_risk.plot(kind='bar', stacked=True, ax=plt.gca(), color=colors, width=0.6)
    plt.title("Review Recommendation by Risk Rating")
    return fig_to_base64()

# 8️⃣ Top Applicants by Submission Count
def plot_top_applicants_a(df):
    plt.figure(figsize=(8,4))
    top_counts = df['applicant_name'].value_counts().head(10)
    colors = random_palette(len(top_counts))
    top_counts.plot(kind='bar', color=colors, width=0.6)
    plt.title("Top Applicants by Submission Count")
    return fig_to_base64()

# 9️⃣ Percentage of Certificates Received
def plot_certificate_received_percentage_a(df):
    plt.figure(figsize=(6,6))
    counts = df['certificate_received'].value_counts(normalize=True) * 100
    counts.plot(kind='pie', autopct='%1.1f%%', colors=random_palette(len(counts)))
    plt.title("Percentage of Certificates Received")
    plt.ylabel("")
    return fig_to_base64()

# 🔟 Review Recommendation Comparison (Primary vs Secondary)
def plot_review_recommendation_comparison_a(df):
    plt.figure(figsize=(8,4))
    categories = df['review_recommendation1'].nunique()
    palette = random_palette(categories)
    sns.countplot(x="review_recommendation1", hue="review_recommendation", data=df, palette=palette, dodge=True)
    plt.title("Primary vs Secondary Review Recommendation")
    plt.xticks(rotation=45)
    return fig_to_base64()

# 1️⃣1️⃣ Number of Applications Received vs Number of Certificates Issued
def plot_applications_vs_certificates_a(df):
    # Deduplicate by form ID so each application is counted only once
    df_unique = df.drop_duplicates(subset=['id'])
    
    applications_count = len(df_unique)  # total unique applications
    certificates_count = df_unique['certificate_issued'].notna().sum()  # issued certificates
    
    data = pd.DataFrame({
        'Category': ['Applications Received', 'Certificates Issued'],
        'Count': [applications_count, certificates_count]
    })
    
    plt.figure(figsize=(6,4))
    sns.barplot(x='Category', y='Count', data=data, palette=random_palette(2), width=0.6)
    plt.title("Applications Received vs Certificates Issued")
    return fig_to_base64()



###
### PLOT FORM B
###

# 1️⃣ Count of Applications by Risk Rating
def plot_risk_rating_distribution_b(df):
    plt.figure(figsize=(6,4))
    categories = df['risk_level'].nunique()
    sns.countplot(x="risk_level", data=df, palette=random_palette(categories), width=0.6)
    plt.title("Applications by Risk Rating")
    return fig_to_base64()

# 2️⃣ Review Recommendations Breakdown
def plot_review_recommendations_b(df):
    plt.figure(figsize=(6,4))
    categories = df['review_recommendation'].nunique()
    sns.countplot(x="review_recommendation", data=df, palette=random_palette(categories), width=0.6)
    plt.title("Review Recommendations")
    plt.xticks(rotation=45)
    return fig_to_base64()

# 3️⃣ Supervisor Recommendations Breakdown
def plot_supervisor_recommendations_b(df):
    plt.figure(figsize=(6,4))
    categories = df['supervisor_recommendation'].nunique()
    sns.countplot(x="supervisor_recommendation", data=df, palette=random_palette(categories), width=0.6)
    plt.title("Supervisor Recommendations")
    plt.xticks(rotation=45)
    return fig_to_base64()

# 4️⃣ Number of Applications per REC Member
def plot_rec_member_distribution_b(df):
    plt.figure(figsize=(6,4))
    categories = df['rec_full_name'].nunique()
    sns.countplot(y="rec_full_name", data=df, palette=random_palette(categories), width=0.6)
    plt.title("Applications Reviewed by Each REC Member")
    return fig_to_base64()

# 5️⃣ Certificate Issued vs Not Issued
def plot_certificate_status_b(df):
    plt.figure(figsize=(6,4))
    categories = df['certificate_issued'].nunique()
    sns.countplot(x="certificate_issued", data=df, palette=random_palette(categories), width=0.6)
    plt.title("Certificate Issuance Status")
    return fig_to_base64()

# 6️⃣ Applications Submitted Over Time
def plot_submissions_over_time_b(df):
    df['submitted_at'] = pd.to_datetime(df['submitted_at'], errors='coerce')
    plt.figure(figsize=(8,4))
    df.groupby(df['submitted_at'].dt.date).size().plot(kind='bar', color=random_palette(df['submitted_at'].dt.date.nunique()), width=0.6)
    plt.title("Submissions Over Time")
    plt.xlabel("Date")
    plt.ylabel("Number of Submissions")
    return fig_to_base64()

# 7️⃣ Review Recommendation by Risk Rating (stacked bar)
def plot_review_by_risk_rating_b(df):
    plt.figure(figsize=(8,4))
    review_risk = pd.crosstab(df['risk_level'], df['review_recommendation'])
    colors = random_palette(review_risk.shape[1])
    review_risk.plot(kind='bar', stacked=True, ax=plt.gca(), color=colors, width=0.6)
    plt.title("Review Recommendation by Risk Rating")
    return fig_to_base64()

# 8️⃣ Top Applicants by Submission Count
def plot_top_applicants_b(df):
    plt.figure(figsize=(8,4))
    top_counts = df['applicant_name'].value_counts().head(10)
    colors = random_palette(len(top_counts))
    top_counts.plot(kind='bar', color=colors, width=0.6)
    plt.title("Top Applicants by Submission Count")
    return fig_to_base64()

# 9️⃣ Percentage of Certificates Received
def plot_certificate_received_percentage_b(df):
    plt.figure(figsize=(6,6))
    counts = df['certificate_received'].value_counts(normalize=True) * 100
    counts.plot(kind='pie', autopct='%1.1f%%', colors=random_palette(len(counts)))
    plt.title("Percentage of Certificates Received")
    plt.ylabel("")
    return fig_to_base64()

# 🔟 Review Recommendation Comparison (Primary vs Secondary)
def plot_review_recommendation_comparison_b(df):
    plt.figure(figsize=(8,4))
    categories = df['review_recommendation1'].nunique()
    palette = random_palette(categories)
    sns.countplot(x="review_recommendation1", hue="review_recommendation", data=df, palette=palette, dodge=True)
    plt.title("Primary vs Secondary Review Recommendation")
    plt.xticks(rotation=45)
    return fig_to_base64()


# 1️⃣1️⃣ Number of Applications Received vs Number of Certificates Issued
def plot_applications_vs_certificates_b(df):
    # Deduplicate by form ID so each application is counted only once
    df_unique = df.drop_duplicates(subset=['id'])
    
    applications_count = len(df_unique)  # total unique applications
    certificates_count = df_unique['certificate_issued'].notna().sum()  # issued certificates
    
    data = pd.DataFrame({
        'Category': ['Applications Received', 'Certificates Issued'],
        'Count': [applications_count, certificates_count]
    })
    
    plt.figure(figsize=(6,4))
    sns.barplot(x='Category', y='Count', data=data, palette=random_palette(2), width=0.6)
    plt.title("Applications Received vs Certificates Issued")
    return fig_to_base64()


###
### PLOT FORM C
###

# 1️⃣ Count of Applications by Risk Rating
def plot_risk_rating_distribution_c(df):
    plt.figure(figsize=(6,4))
    categories = df['risk_level'].nunique()
    sns.countplot(x="risk_level", data=df, palette=random_palette(categories), width=0.6)
    plt.title("Applications by Risk Rating")
    return fig_to_base64()

# 2️⃣ Review Recommendations Breakdown
def plot_review_recommendations_c(df):
    plt.figure(figsize=(6,4))
    categories = df['review_recommendation'].nunique()
    sns.countplot(x="review_recommendation", data=df, palette=random_palette(categories), width=0.6)
    plt.title("Review Recommendations")
    plt.xticks(rotation=45)
    return fig_to_base64()

# 3️⃣ Supervisor Recommendations Breakdown
def plot_supervisor_recommendations_c(df):
    plt.figure(figsize=(6,4))
    categories = df['supervisor_recommendation'].nunique()
    sns.countplot(x="supervisor_recommendation", data=df, palette=random_palette(categories), width=0.6)
    plt.title("Supervisor Recommendations")
    plt.xticks(rotation=45)
    return fig_to_base64()

# 4️⃣ Number of Applications per REC Member
def plot_rec_member_distribution_c(df):
    plt.figure(figsize=(6,4))
    categories = df['rec_full_name'].nunique()
    sns.countplot(y="rec_full_name", data=df, palette=random_palette(categories), width=0.6)
    plt.title("Applications Reviewed by Each REC Member")
    return fig_to_base64()

# 5️⃣ Certificate Issued vs Not Issued
def plot_certificate_status_c(df):
    plt.figure(figsize=(6,4))
    categories = df['certificate_issued'].nunique()
    sns.countplot(x="certificate_issued", data=df, palette=random_palette(categories), width=0.6)
    plt.title("Certificate Issuance Status")
    return fig_to_base64()

# 6️⃣ Applications Submitted Over Time
def plot_submissions_over_time_c(df):
    df['submission_date'] = pd.to_datetime(df['submission_date'], errors='coerce')
    plt.figure(figsize=(8,4))
    df.groupby(df['submission_date'].dt.date).size().plot(kind='bar', color=random_palette(df['submission_date'].dt.date.nunique()), width=0.6)
    plt.title("Submissions Over Time")
    plt.xlabel("Date")
    plt.ylabel("Number of Submissions")
    return fig_to_base64()

# 7️⃣ Review Recommendation by Risk Rating (stacked bar)
def plot_review_by_risk_rating_c(df):
    plt.figure(figsize=(8,4))
    review_risk = pd.crosstab(df['risk_rating'], df['review_recommendation'])
    colors = random_palette(review_risk.shape[1])
    review_risk.plot(kind='bar', stacked=True, ax=plt.gca(), color=colors, width=0.6)
    plt.title("Review Recommendation by Risk Rating")
    return fig_to_base64()

# 8️⃣ Top Applicants by Submission Count
def plot_top_applicants_c(df):
    plt.figure(figsize=(8,4))
    top_counts = df['applicant_name'].value_counts().head(10)
    colors = random_palette(len(top_counts))
    top_counts.plot(kind='bar', color=colors, width=0.6)
    plt.title("Top Applicants by Submission Count")
    return fig_to_base64()

# 9️⃣ Percentage of Certificates Received
def plot_certificate_received_percentage_c(df):
    plt.figure(figsize=(6,6))
    counts = df['certificate_received'].value_counts(normalize=True) * 100
    counts.plot(kind='pie', autopct='%1.1f%%', colors=random_palette(len(counts)))
    plt.title("Percentage of Certificates Received")
    plt.ylabel("")
    return fig_to_base64()

# 🔟 Review Recommendation Comparison (Primary vs Secondary)
def plot_review_recommendation_comparison_c(df):
    plt.figure(figsize=(8,4))
    categories = df['review_recommendation1'].nunique()
    palette = random_palette(categories)
    sns.countplot(x="review_recommendation1", hue="review_recommendation", data=df, palette=palette, dodge=True)
    plt.title("Primary vs Secondary Review Recommendation")
    plt.xticks(rotation=45)
    return fig_to_base64()

# 1️⃣1️⃣ Number of Applications Received vs Number of Certificates Issued
def plot_applications_vs_certificates_c(df):
    # Deduplicate by form ID so each application is counted only once
    df_unique = df.drop_duplicates(subset=['id'])
    
    applications_count = len(df_unique)  # total unique applications
    certificates_count = df_unique['certificate_issued'].notna().sum()  # issued certificates
    
    data = pd.DataFrame({
        'Category': ['Applications Received', 'Certificates Issued'],
        'Count': [applications_count, certificates_count]
    })
    
    plt.figure(figsize=(6,4))
    sns.barplot(x='Category', y='Count', data=data, palette=random_palette(2), width=0.6)
    plt.title("Applications Received vs Certificates Issued")
    return fig_to_base64()


