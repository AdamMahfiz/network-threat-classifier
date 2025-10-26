# UI Wireframes - Network Threat Classification System

## 1. Login Page Wireframe

```
┌─────────────────────────────────────────────────────────────┐
│                    NETWORK THREAT CLASSIFIER                │
│                                                             │
│    ┌─────────────────────────────────────────────────┐    │
│    │                 LOGIN FORM                      │    │
│    │                                                 │    │
│    │  Email:    [________________________]          │    │
│    │                                                 │    │
│    │  Password: [________________________]          │    │
│    │                                                 │    │
│    │            [    LOGIN BUTTON    ]              │    │
│    │                                                 │    │
│    │  □ Remember Me    [Forgot Password?]           │    │
│    │                                                 │    │
│    │            [Register New Account]              │    │
│    └─────────────────────────────────────────────────┘    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 2. Dashboard (Main Page) Wireframe

```
┌─────────────────────────────────────────────────────────────┐
│ [LOGO] Network Threat Classifier    [Profile] [Logout]     │
├─────────────────────────────────────────────────────────────┤
│ [Dashboard] [Monitor] [Audit] [Users*]                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              THREAT ANALYSIS SECTION                │   │
│  │                                                     │   │
│  │  Upload File: [Choose File] [Upload]               │   │
│  │                                                     │   │
│  │  OR                                                 │   │
│  │                                                     │   │
│  │  Text Input:                                        │   │
│  │  ┌─────────────────────────────────────────────┐   │   │
│  │  │                                             │   │   │
│  │  │         [Paste log data here]               │   │   │
│  │  │                                             │   │   │
│  │  └─────────────────────────────────────────────┘   │   │
│  │                                                     │   │
│  │              [ANALYZE THREAT]                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                RECENT RESULTS                       │   │
│  │                                                     │   │
│  │  • Analysis #1 - Normal Traffic    [View Details]  │   │
│  │  • Analysis #2 - DoS Attack        [View Details]  │   │
│  │  • Analysis #3 - Port Scan         [View Details]  │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 3. Real-time Monitoring Page Wireframe

```
┌─────────────────────────────────────────────────────────────┐
│ [LOGO] Network Threat Classifier    [Profile] [Logout]     │
├─────────────────────────────────────────────────────────────┤
│ [Dashboard] [Monitor] [Audit] [Users*]                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │            MONITORING STATUS                        │   │
│  │                                                     │   │
│  │  Status: ● ACTIVE    Last Update: 12:34:56        │   │
│  │                                                     │   │
│  │  [START MONITORING] [STOP MONITORING]              │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                LIVE THREATS                         │   │
│  │                                                     │   │
│  │  ┌─────────────────────────────────────────────┐   │   │
│  │  │ 12:34:56 | DoS Attack | 192.168.1.100      │   │   │
│  │  │ 12:33:45 | Port Scan  | 10.0.0.50          │   │   │
│  │  │ 12:32:12 | Normal     | 192.168.1.200      │   │   │
│  │  │ 12:31:08 | Probe      | 172.16.0.10        │   │   │
│  │  └─────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              THREAT STATISTICS                      │   │
│  │                                                     │   │
│  │  [    PIE CHART OF THREAT TYPES    ]               │   │
│  │                                                     │   │
│  │  Normal: 65%  DoS: 20%  Probe: 10%  Other: 5%     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 4. User Management Page Wireframe (Admin Only)

```
┌─────────────────────────────────────────────────────────────┐
│ [LOGO] Network Threat Classifier    [Profile] [Logout]     │
├─────────────────────────────────────────────────────────────┤
│ [Dashboard] [Monitor] [Audit] [Users*]                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              USER MANAGEMENT                        │   │
│  │                                                     │   │
│  │  [ADD NEW USER]              Search: [_________]   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                 USER LIST                           │   │
│  │                                                     │   │
│  │ ┌─────┬──────────────┬──────┬──────┬─────────────┐ │   │
│  │ │ ID  │ Email        │ Role │ 2FA  │ Actions     │ │   │
│  │ ├─────┼──────────────┼──────┼──────┼─────────────┤ │   │
│  │ │ 1   │ admin@ex.com │Admin │ ✓    │[Edit][Del]  │ │   │
│  │ │ 2   │ user@ex.com  │User  │ ✗    │[Edit][Del]  │ │   │
│  │ │ 3   │ test@ex.com  │User  │ ✓    │[Edit][Del]  │ │   │
│  │ └─────┴──────────────┴──────┴──────┴─────────────┘ │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              ADD/EDIT USER FORM                     │   │
│  │                                                     │   │
│  │  Email:    [________________________]              │   │
│  │  Password: [________________________]              │   │
│  │  Role:     [Admin ▼]                               │   │
│  │  2FA:      □ Enable Two-Factor Authentication      │   │
│  │                                                     │   │
│  │            [SAVE USER] [CANCEL]                    │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 5. Audit Log Page Wireframe (Admin Only)

```
┌─────────────────────────────────────────────────────────────┐
│ [LOGO] Network Threat Classifier    [Profile] [Logout]     │
├─────────────────────────────────────────────────────────────┤
│ [Dashboard] [Monitor] [Audit] [Users*]                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                AUDIT LOG FILTERS                    │   │
│  │                                                     │   │
│  │  Date Range: [From: ____] [To: ____]               │   │
│  │  User: [All Users ▼]  Action: [All Actions ▼]     │   │
│  │                                                     │   │
│  │              [APPLY FILTERS] [RESET]               │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  AUDIT ENTRIES                      │   │
│  │                                                     │   │
│  │ ┌──────────┬─────────────┬─────────┬─────────────┐  │   │
│  │ │Timestamp │ User        │ Action  │ Details     │  │   │
│  │ ├──────────┼─────────────┼─────────┼─────────────┤  │   │
│  │ │12:34:56  │admin@ex.com │ Login   │ Successful  │  │   │
│  │ │12:33:45  │user@ex.com  │ Analyze │ File upload │  │   │
│  │ │12:32:12  │admin@ex.com │ User+   │ Added user  │  │   │
│  │ │12:31:08  │user@ex.com  │ Login   │ Failed 2FA  │  │   │
│  │ └──────────┴─────────────┴─────────┴─────────────┘  │   │
│  │                                                     │   │
│  │              [EXPORT LOG] [REFRESH]                │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## 6. Profile Management Page Wireframe

```
┌─────────────────────────────────────────────────────────────┐
│ [LOGO] Network Threat Classifier    [Profile] [Logout]     │
├─────────────────────────────────────────────────────────────┤
│ [Dashboard] [Monitor] [Audit] [Users*]                     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              PROFILE INFORMATION                    │   │
│  │                                                     │   │
│  │  First Name: [________________________]            │   │
│  │  Last Name:  [________________________]            │   │
│  │  Email:      [________________________]            │   │
│  │                                                     │   │
│  │              [UPDATE PROFILE]                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              CHANGE PASSWORD                        │   │
│  │                                                     │   │
│  │  Current Password: [________________________]       │   │
│  │  New Password:     [________________________]       │   │
│  │  Confirm Password: [________________________]       │   │
│  │                                                     │   │
│  │              [CHANGE PASSWORD]                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │          TWO-FACTOR AUTHENTICATION                  │   │
│  │                                                     │   │
│  │  Status: ● ENABLED / ○ DISABLED                    │   │
│  │                                                     │   │
│  │  [QR CODE IMAGE]                                   │   │
│  │                                                     │   │
│  │  Verification Code: [____________]                 │   │
│  │                                                     │   │
│  │  [ENABLE 2FA] [DISABLE 2FA] [VERIFY]              │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Design Notes for Chapter 6:

### 1. Layout Structure
- **Header**: Logo, navigation menu, user profile dropdown
- **Navigation**: Horizontal tab-based navigation
- **Content Area**: Card-based layout with rounded corners
- **Responsive Design**: Mobile-friendly with collapsible navigation

### 2. Color Scheme
- **Primary**: Blue gradient (#667eea to #764ba2)
- **Secondary**: Dark theme with light cards
- **Accent Colors**: Green (success), Red (danger), Orange (warning)
- **Text**: High contrast for accessibility

### 3. Key UI Components
- **Cards**: Rounded corners with shadows for content sections
- **Forms**: Clean input fields with proper spacing
- **Tables**: Sortable columns with action buttons
- **Charts**: Interactive charts for data visualization
- **Buttons**: Gradient backgrounds with hover effects

### 4. User Experience Features
- **Real-time Updates**: Live monitoring with WebSocket connections
- **Progressive Disclosure**: Collapsible sections for detailed information
- **Feedback**: Toast notifications for user actions
- **Loading States**: Spinners and progress indicators
- **Error Handling**: Clear error messages and recovery options

### 5. Accessibility Considerations
- **Keyboard Navigation**: Full keyboard support
- **Screen Reader Support**: Proper ARIA labels
- **Color Contrast**: WCAG 2.1 AA compliance
- **Font Sizes**: Scalable text for different screen sizes

### 6. Security UI Elements
- **2FA Setup**: QR code generation and verification
- **Session Management**: Clear session timeout indicators
- **Role-based Access**: Different UI elements based on user permissions
- **Audit Trail**: Comprehensive logging interface for administrators