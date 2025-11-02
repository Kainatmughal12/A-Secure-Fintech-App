# Debt Payoff Planner

**Debt Payoff Planner** is a secure, FinTech web application designed to help users manage and track personal debts while providing accurate payoff calculations. The app combines functional debt management with robust security practices, offering a reliable and user-friendly financial management tool.

## Features

### Debt Management
- **Add, View, Edit, Delete Debts**: Manage debts with details such as name, balance, interest rate, and monthly payment.
- **Payoff Calculations**: Calculates months to payoff, total interest, and overall debt payoff.
- **Visual Tracking**: Progress bars and summary cards for individual debts and total debt overview.

### Security
- **Authentication & Authorization**: Password hashing, session management, and account lockout after 5 failed attempts.
- **Input Validation & Sanitization**: Prevents XSS, SQL injection, Unicode/emoji misuse, and other attacks.
- **File Upload Validation**: Accepts only safe file types (JPG, PNG, PDF) with size and MIME checks.
- **Encrypted Storage**: User data encrypted in localStorage (simulated) with per-user isolation.
- **Audit Logging**: Records security events and user actions for monitoring.

### Additional
- Responsive, mobile-friendly dark theme with smooth animations.
- Clear, intuitive UI with glassmorphism effects.

## Technology Stack
- **Frontend:** HTML5, CSS3 (responsive, dark theme, glassmorphism)
- **Logic:** Vanilla JavaScript (modular)
- **Storage:** LocalStorage (encrypted/simulated secure storage)

## User Flow
1. **Register/Login**: Secure authentication required.
2. **Dashboard**: Access and manage debts after login.
3. **Debt Management**: Add, edit, or remove debts.
4. **Payoff Calculations**: Automatic computation of months to payoff and total interest.
5. **Visual Tracking**: See progress via debt cards and summary cards.
6. **File Uploads**: Upload documents with strict file type validation.
7. **Security Testing**: Access 20 manual cybersecurity test cases.
8. **Audit Logs**: View historical security and user events.

## Installation & Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/debt-payoff-planner.git
