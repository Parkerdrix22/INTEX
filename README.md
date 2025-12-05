# Ella Rises Website - TA Grading Documentation

## Website URL
**Production URL:** https://04-03-ellarises.is404.net/

## Login Credentials

### Admin/Manager Account
- **Username:** `nadiacates-admin`
- **Password:** `admin`
- **Access Level:** Manager (Full administrative access)

### Regular User Account
- **Username:** `nadiacates-user`
- **Password:** `user`
- **Access Level:** User (Standard participant access)

## Getting Started

1. Navigate to the website URL: https://04-03-ellarises.is404.net/
2. Click **"Sign In / Create Account"** in the top right corner
3. Enter the admin credentials to access manager features
4. Use the regular user account to test participant-facing features

## Key Features for Grading

### Admin/Manager Features (nadiacates-admin)

#### 1. **Participants Page** (`/participants`)
- View all participants in the system
- Add, edit, and delete participants
- Search participants by name or email
- View participant details including:
  - Personal information (name, email, DOB, contact info)
  - User account details (username, password, access level)
  - School/employer information
- **Note:** Passwords are displayed as dots (`••••••`) for security

#### 2. **Events Page** (`/events`)
- View all events
- Add new events
- Edit and delete events
- Filter and search events
- Click on events to view registrations (manager only)
- View past occurrences and registrations

#### 3. **Reservations/Check-in Page** (`/reservations/:id`)
- Accessible by clicking on an event from the events page (manager only)
- View all registered participants for an event
- Check-in participants with date/time
- Update registration status:
  - Attended
  - No-Show
  - Cancelled
- View status totals for past occurrences
- Switch between future and past event occurrences

#### 4. **Event Feedback/Survey Page** (`/survey`)
- View all events with feedback surveys
- Edit survey questions for each event
- Add custom questions to surveys
- Delete surveys
- View survey responses
- Search events by name

#### 5. **Milestones Page** (`/milestones`)
- Search for participants to view their personal milestones
- View milestone completion statistics
- Select a milestone to see:
  - Total number of participants who completed it
  - Percentage of all participants who completed it
  - Timeline graph showing completions over time
- View total milestones overview graph (all milestones combined)

#### 6. **Personal Milestones Page** (`/personal-milestones?participantId=X`)
- View individual participant milestones
- Add, edit, and delete milestones (admin only)
- View event attendance progress
- See milestone timeline with year navigation

#### 7. **Donations Page** (`/donations`)
- View donation analytics (manager only):
  - Total number of donations
  - Total donation amount (rounded to nearest dollar)
- Search for participants by first or last name
- View individual participant donation history
- Add, edit, and delete donations (manager only)
- Regular users can submit donations (requires sign-in)

#### 8. **Impact Dashboard** (`/dashboard`)
- View Tableau dashboard with key indicators
- Visual analytics and metrics
- Manager-only access

### Regular User Features (nadiacates-user)

#### 1. **Events Page** (`/events`)
- View all public events
- RSVP for events
- View event details

#### 2. **RSVP Page** (`/rsvp/:id`)
- RSVP for future event dates only
- View event information
- See RSVP confirmation

#### 3. **Event Feedback** (`/survey`)
- Fill out post-event surveys
- Provide feedback on events attended

#### 4. **My Journey** (`/my-journey`)
- View personal milestones
- Track event attendance progress
- See milestone timeline

#### 5. **Donations** (`/donations`)
- Submit donations
- Select donation amount
- Enter payment information (redirects to external payment processor)

#### 6. **Profile** (`/profile`)
- View and edit personal information
- Update contact details

## Navigation Structure

### Manager Navigation Bar
- **Participants** (manager only)
- **Events**
- **Event Feedback**
- **Milestones** (manager only)
- **Donations**
- **Dashboard** (manager only)

### Regular User Navigation Bar
- **Events**
- **Event Feedback**
- **My Journey | Mi Camino**
- **Donations**

## Database Tables Reference

### Key Tables for Grading
- **`participants`** - Participant information
- **`users`** - User accounts (linked to participants)
- **`events`** - Event definitions
- **`eventoccurrence`** - Specific event dates/times
- **`registration`** - Event registrations (composite key: participantid, eventoccurrenceid)
- **`milestones`** - Milestone completions (composite key: participantid, milestonetitle, milestonedate)
- **`donations`** - Donation records
- **`surveyresponses`** - Survey answers
- **`surveyquestions`** - Custom survey questions

## Important Notes for Grading

1. **Manager vs User Access**: Many features are restricted to managers. Use the admin account to test all functionality.

2. **Composite Primary Keys**:
   - Registrations use: `(participantid, eventoccurrenceid)`
   - Milestones use: `(participantid, milestonetitle, milestonedate)`

3. **Email Uniqueness**: The system enforces unique email addresses per participant.

4. **Password Display**: Passwords are shown as dots in the participants table for security.

5. **Responsive Design**: The website is responsive and works on desktop and mobile devices.

6. **Tableau Dashboard**: The dashboard requires proper CSP (Content Security Policy) settings and may take a moment to load.

## Testing Checklist

### Manager Features
- [ ] Login with admin credentials
- [ ] View participants list
- [ ] Add/edit/delete participants
- [ ] Create and manage events
- [ ] View event registrations
- [ ] Check-in participants
- [ ] Update registration status
- [ ] Edit survey questions
- [ ] View milestone statistics
- [ ] Manage donations
- [ ] View dashboard

### User Features
- [ ] Login with user credentials
- [ ] RSVP for events
- [ ] Submit event feedback
- [ ] View personal milestones
- [ ] Submit donations
- [ ] Update profile


