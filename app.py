from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import pandas as pd
import os
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
from sqlalchemy import func # Import func for count
import io # Add io for creating file in memory


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_very_secret_key_here' # Change this in production!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voting.db' # Using SQLite for simplicity
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'xlsx', 'pdf', 'png', 'jpg', 'jpeg'}

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'admin_login' # Redirect to admin_login if user tries to access protected page


# --- Database Models ---

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        # Use bcrypt for password hashing
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

class Voter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    faculty = db.Column(db.String(100), nullable=False)
    has_voted = db.Column(db.Boolean, default=False)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    photo_path = db.Column(db.String(200))
    vision_mission_path = db.Column(db.String(200)) # PDF path
    vision_mission_text = db.Column(db.Text) # Manual text input
    votes = db.Column(db.Integer, default=0)
    faculty_votes = db.relationship('FacultyVote', backref='candidate', lazy=True, cascade="all, delete-orphan")

class FacultyVote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    faculty_name = db.Column(db.String(100), nullable=False)
    vote_count = db.Column(db.Integer, default=0)
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'), nullable=False)


class VotingSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_time = db.Column(db.DateTime)
    end_time = db.Column(db.DateTime)
    voting_password_hash = db.Column(db.String(128)) # Store hash of the voting password
    published = db.Column(db.Boolean, default=False) # Tracks if the vote is live

    def set_voting_password(self, password):
         if password: # Only hash if a password is provided
            self.voting_password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
         else:
             self.voting_password_hash = None # Allow clearing the password


    def check_voting_password(self, password):
         if not self.voting_password_hash: # No password set
            return False # Or True, depending on desired behavior if no password is set
         return bcrypt.checkpw(password.encode('utf-8'), self.voting_password_hash.encode('utf-8'))


@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

# --- Helper Functions ---

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# --- Routes ---

@app.route('/')
def index():
    # This will eventually lead to the voting page or a holding page
    return "Welcome to the Voting App!"

# --- Admin Routes ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
     if current_user.is_authenticated:
        return redirect(url_for('admin_dashboard'))

     if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            login_user(admin)
            flash('Login berhasil!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Username atau password salah.', 'danger')
     return render_template('admin_login.html') # We'll create this template later

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('admin_login'))


@app.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
    # Fetch current settings, candidates, and voter count for display
    settings = VotingSettings.query.first()
    candidates = Candidate.query.order_by(Candidate.name).all()
    voter_count = db.session.query(func.count(Voter.id)).scalar()

    # Determine voting status
    status = "Not Configured"
    now = datetime.now()
    if settings:
        # Revert to previous status logic
        if settings.published:
            if settings.end_time and now > settings.end_time:
                status = "Finished"
            elif settings.start_time and now < settings.start_time:
                status = "Published (Scheduled)"
            else:
                status = "Active"
        else:
            # Original simpler check for readiness
            if settings.start_time and settings.end_time and settings.voting_password_hash:
                 status = "Ready to Publish"
            else:
                 status = "Configuring (Not Published)"


    return render_template('admin_dashboard.html',
                           settings=settings,
                           candidates=candidates,
                           voter_count=voter_count,
                           voting_status=status,
                           current_time=now)


@app.route('/admin/setup_admin', methods=['GET', 'POST'])
def setup_admin():
    # Check if an admin already exists
    if Admin.query.first():
        flash('User admin sudah ada. Silakan login.', 'warning')
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Password tidak cocok!', 'danger')
            return render_template('setup_admin.html')

        if Admin.query.filter_by(username=username).first():
             flash('Username sudah ada.', 'danger')
             return render_template('setup_admin.html')


        new_admin = Admin(username=username)
        new_admin.set_password(password)
        db.session.add(new_admin)
        db.session.commit()
        flash('Akun admin berhasil dibuat! Silakan login.', 'success')
        return redirect(url_for('admin_login'))

    # Show the setup form if no admin exists
    return render_template('setup_admin.html') # We'll create this template later


# --- Placeholder routes for future implementation ---

@app.route('/admin/new_vote', methods=['POST'])
@login_required
def new_vote():
    # Logic to reset/initialize a new voting session
    # Clear existing candidates, voters (optional), settings?
    # Or create a new "Election" concept if multiple are needed over time.
    # For now, let's clear candidates and voters, and reset settings.

    try:
        # Delete related FacultyVote entries first due to foreign key constraints
        FacultyVote.query.delete()
        # Now delete Candidates
        Candidate.query.delete()
        # Delete Voters
        Voter.query.delete()
         # Reset Voting Settings (or create if not exists)
        settings = VotingSettings.query.first()
        if settings:
            settings.start_time = None
            settings.end_time = None
            settings.set_voting_password(None) # Clear password hash
            settings.published = False
        else:
             # If no settings exist, create a default record
             settings = VotingSettings()
             db.session.add(settings)

        db.session.commit()
        flash('Pemilihan baru telah diinisialisasi. Data sebelumnya dihapus.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal menginisialisasi pemilihan baru: {str(e)}', 'danger')

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/upload_voters', methods=['POST'])
@login_required
def upload_voters():
    if 'voter_file' not in request.files:
        flash('Tidak ada file yang diunggah', 'danger')
        return redirect(url_for('admin_dashboard'))
    file = request.files['voter_file']
    if file.filename == '':
        flash('Tidak ada file yang dipilih', 'danger')
        return redirect(url_for('admin_dashboard'))
    if file and allowed_file(file.filename) and file.filename.endswith('.xlsx'):
        try:
            # Clear existing voters before uploading new list
            Voter.query.delete()
            db.session.commit()

            df = pd.read_excel(file)
            # Basic validation - check for required columns
            required_cols = ['name', 'id', 'faculty'] # Adjust column names as needed
            if not all(col in df.columns for col in required_cols):
                 flash(f'File Excel harus memiliki kolom: {", ".join(required_cols)}', 'danger')
                 return redirect(url_for('admin_dashboard'))


            for index, row in df.iterrows():
                voter = Voter(
                    student_id=str(row['id']), # Ensure ID is string
                    name=row['name'],
                    faculty=row['faculty']
                )
                db.session.add(voter)
            db.session.commit()
            flash('Daftar pemilih berhasil diunggah!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Gagal memproses file Excel: {str(e)}', 'danger')
    else:
        flash('Tipe file tidak valid. Harap unggah file Excel (.xlsx).', 'danger')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/add_candidate', methods=['POST'])
@login_required
def add_candidate():
    name = request.form.get('candidate_name')
    vision_mission_text = request.form.get('vision_mission_text')
    photo = request.files.get('candidate_photo')
    vision_mission_pdf = request.files.get('vision_mission_pdf')

    if not name:
        flash('Nama kandidat harus diisi.', 'danger')
        return redirect(url_for('admin_dashboard'))

    photo_path = None
    pdf_path = None

    # Handle photo upload
    if photo and allowed_file(photo.filename):
        filename = secure_filename(f"candidate_{name.replace(' ','_')}_photo.{photo.filename.rsplit('.', 1)[1].lower()}")
        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
             photo.save(photo_path)
             photo_path = filename # Store relative path for db/template usage
        except Exception as e:
             flash(f'Gagal menyimpan foto: {str(e)}', 'danger')
             photo_path = None # Reset on error

    # Handle PDF upload
    if vision_mission_pdf and allowed_file(vision_mission_pdf.filename) and vision_mission_pdf.filename.endswith('.pdf'):
        filename = secure_filename(f"candidate_{name.replace(' ','_')}_vm.{vision_mission_pdf.filename.rsplit('.', 1)[1].lower()}")
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            vision_mission_pdf.save(pdf_path)
            pdf_path = filename # Store relative path
        except Exception as e:
             flash(f'Gagal menyimpan PDF: {str(e)}', 'danger')
             pdf_path = None # Reset on error


    # Ensure vision/mission text is saved if PDF fails or isn't provided
    if not pdf_path and not vision_mission_text:
         flash('Diperlukan file PDF Visi/Misi atau input teks.', 'danger')
         # Clean up saved photo if validation fails here
         if photo_path:
              try:
                   os.remove(os.path.join(app.config['UPLOAD_FOLDER'], photo_path))
              except OSError:
                   pass # Ignore error if file doesn't exist
         return redirect(url_for('admin_dashboard'))


    try:
        new_candidate = Candidate(
            name=name,
            photo_path=photo_path,
            vision_mission_path=pdf_path,
            vision_mission_text=vision_mission_text if not pdf_path else None # Prioritize PDF if both provided
        )
        db.session.add(new_candidate)
        db.session.commit()
        flash(f'Kandidat {name} berhasil ditambahkan!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal menambahkan kandidat: {str(e)}', 'danger')
         # Clean up uploaded files on DB error
        if photo_path:
             try:
                  os.remove(os.path.join(app.config['UPLOAD_FOLDER'], photo_path))
             except OSError: pass
        if pdf_path:
             try:
                  os.remove(os.path.join(app.config['UPLOAD_FOLDER'], pdf_path))
             except OSError: pass


    return redirect(url_for('admin_dashboard'))


@app.route('/admin/settings', methods=['POST'])
@login_required
def update_settings():
    start_time_str = request.form.get('start_time')
    end_time_str = request.form.get('end_time')
    voting_password = request.form.get('voting_password') # New password or empty

    settings = VotingSettings.query.first()
    if not settings:
        settings = VotingSettings()
        db.session.add(settings)

    try:
        if start_time_str:
             settings.start_time = datetime.fromisoformat(start_time_str)
        else:
             settings.start_time = None


        if end_time_str:
             settings.end_time = datetime.fromisoformat(end_time_str)
        else:
             settings.end_time = None

        # Only update password if a new one is provided
        if voting_password:
             settings.set_voting_password(voting_password)


        db.session.commit()
        flash('Pengaturan pemilihan berhasil diperbarui!', 'success')
    except ValueError:
         flash('Format tanggal/waktu tidak valid. Gunakan YYYY-MM-DDTHH:MM.', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal memperbarui pengaturan: {str(e)}', 'danger')

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/publish_vote', methods=['POST'])
@login_required
def publish_vote():
    # --- Simplified Logic --- 
    # Remove all checks and database operations.
    # This button now acts only as a shortcut to the voter verification page.
    # Actual voting availability still depends on settings configured via the dashboard
    # (start/end time, password, and the unpublished 'published' flag in the DB if needed by other logic).

    # print("DEBUG: Publish button clicked, redirecting to voter_verification.") # Optional: Keep if needed
    flash('Mengarahkan ke halaman Verifikasi Pemilih...', 'info')
    return redirect(url_for('voter_verification'))

    # --- Original Logic (Commented Out) ---
    # print("--- DEBUG: Entered /admin/publish_vote route ---") # LOGGING
    # settings = VotingSettings.query.first()
    # # Check 1: Settings
    # if not settings or not settings.start_time or not settings.end_time or not settings.voting_password_hash:
    #     print("--- DEBUG: Publish check FAILED: Settings incomplete ---") # LOGGING
    #     flash('Cannot publish. Please set start time, end time, and voting password first.', 'warning')
    #     return redirect(url_for('admin_dashboard'))
    # print("--- DEBUG: Publish check PASSED: Settings complete ---") # LOGGING
    # # Check 2: Candidates
    # if not Candidate.query.first():
    #      print("--- DEBUG: Publish check FAILED: No candidates ---") # LOGGING
    #      flash('Cannot publish. Please add at least one candidate.', 'warning')
    #      return redirect(url_for('admin_dashboard'))
    # print("--- DEBUG: Publish check PASSED: Candidates exist ---") # LOGGING
    # # Check 3: Voters
    # if not Voter.query.first():
    #       print("--- DEBUG: Publish check FAILED: No voters ---") # LOGGING
    #       flash('Cannot publish. Please upload the voter list.', 'warning')
    #       return redirect(url_for('admin_dashboard'))
    # print("--- DEBUG: Publish check PASSED: Voters exist ---") # LOGGING
    # print("--- DEBUG: All publish checks passed. Attempting to set published=True and redirect. ---") # LOGGING
    # try:
    #     settings.published = True
    #     db.session.commit()
    #     print("--- DEBUG: Publish SUCCESSFUL. Redirecting to voting_auth. ---") # LOGGING
    #     flash('Voting page is now published and live! Voters can now access the voting page.', 'success')
    #     return redirect(url_for('voting_auth')) # Original redirect was here
    # except Exception as e:
    #     db.session.rollback()
    #     print(f"--- DEBUG: Publish EXCEPTION: {e} ---") # LOGGING
    #     flash(f'Error publishing vote: {str(e)}', 'danger')
    #     return redirect(url_for('admin_dashboard'))

@app.route('/admin/results')
@login_required
def admin_results():
    candidates = Candidate.query.order_by(Candidate.votes.desc()).all()
    total_votes = db.session.query(func.sum(Candidate.votes)).scalar() or 0

    # Prepare faculty breakdown data for display (and potential export later)
    faculty_results = {}
    all_faculties = sorted(list(set(fv.faculty_name for fv in FacultyVote.query.all()) | set(v.faculty for v in Voter.query.all())))

    for cand in candidates:
        faculty_results[cand.name] = {}
        for faculty in all_faculties:
            fv = FacultyVote.query.filter_by(candidate_id=cand.id, faculty_name=faculty).first()
            faculty_results[cand.name][faculty] = fv.vote_count if fv else 0

    return render_template('admin_results.html',
                           candidates=candidates,
                           total_votes=total_votes,
                           faculty_results=faculty_results, # Pass faculty data
                           all_faculties=all_faculties)    # Pass faculty list

@app.route('/admin/export_results')
@login_required
def export_results():
    try:
        # Fetch candidates ordered by votes
        candidates = Candidate.query.order_by(Candidate.votes.desc()).all()
        total_votes_cast = db.session.query(func.sum(Candidate.votes)).scalar() or 0

        # Fetch faculty breakdown
        faculty_results_raw = FacultyVote.query.all()
        all_faculties = sorted(list(set(fv.faculty_name for fv in faculty_results_raw) | set(v.faculty for v in Voter.query.all())))

        # Prepare data for DataFrame
        data_for_excel = []
        for rank, cand in enumerate(candidates, 1):
            row = {
                'Rank': rank,
                'Candidate': cand.name,
                'Total Votes': cand.votes
            }
            # Add faculty votes
            for faculty in all_faculties:
                 faculty_vote = FacultyVote.query.filter_by(candidate_id=cand.id, faculty_name=faculty).first()
                 row[f'Votes ({faculty})'] = faculty_vote.vote_count if faculty_vote else 0
            data_for_excel.append(row)

        # Add a summary row
        summary_row = {'Rank': '', 'Candidate': 'TOTAL', 'Total Votes': total_votes_cast}
        for faculty in all_faculties:
             faculty_total = db.session.query(func.sum(FacultyVote.vote_count)).filter(FacultyVote.faculty_name == faculty).scalar() or 0
             summary_row[f'Votes ({faculty})'] = faculty_total
        data_for_excel.append(summary_row)

        df = pd.DataFrame(data_for_excel)

        # Create Excel file in memory
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Voting Results')
            # You could add more sheets if needed

        output.seek(0)

        # Return as file download
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name='voting_results.xlsx'
        )

    except Exception as e:
        flash(f'Gagal membuat ekspor Excel: {str(e)}', 'danger')
        # Log the detailed error for debugging
        app.logger.error(f"Excel Export Error: {str(e)}", exc_info=True)
        return redirect(url_for('admin_results'))


# --- Voting Page Routes ---

@app.route('/vote', methods=['GET', 'POST'])
def voting_page():
     settings = VotingSettings.query.first()
     now = datetime.now()

     # Check if voting is published and within the allowed time
     if not settings or not settings.published:
         flash('Voting is not currently active.', 'info')
         return redirect(url_for('index')) # Or a specific "voting closed" page

     if settings.start_time and now < settings.start_time:
          flash(f'Pemilihan dimulai pada {settings.start_time.strftime("%Y-%m-%d %H:%M:%S")}.', 'info')
          return redirect(url_for('index'))

     if settings.end_time and now > settings.end_time:
          flash(f'Pemilihan berakhir pada {settings.end_time.strftime("%Y-%m-%d %H:%M:%S")}.', 'info')
          return redirect(url_for('index'))


     # Check for voting password in session
     if 'voting_access_granted' not in session:
          return redirect(url_for('voting_auth'))


     # Check for voter verification in session
     if 'voter_id' not in session:
          return redirect(url_for('voter_verification')) # Redirect if voter not verified

     voter = Voter.query.get(session['voter_id'])
     if not voter or voter.has_voted:
        # If voter somehow got here after voting or doesn't exist, clear session and redirect
        session.pop('voter_id', None)
        session.pop('voter_name', None)
        session.pop('voter_faculty', None)
        flash('Anda sudah memilih atau informasi pemilih tidak valid.', 'warning')
        return redirect(url_for('voter_verification'))


     if request.method == 'POST':
        candidate_id = request.form.get('candidate_id')
        if not candidate_id:
             flash('Harap pilih kandidat untuk memilih.', 'warning')
             return redirect(url_for('voting_page'))


        candidate = Candidate.query.get(candidate_id)
        voter = Voter.query.get(session['voter_id']) # Re-fetch voter to be safe

        if candidate and voter and not voter.has_voted:
            try:
                voter.has_voted = True
                candidate.votes += 1

                 # Increment faculty-specific vote count
                faculty_vote = FacultyVote.query.filter_by(candidate_id=candidate.id, faculty_name=voter.faculty).first()
                if faculty_vote:
                    faculty_vote.vote_count += 1
                else:
                    # Create a new entry if this is the first vote from this faculty for this candidate
                    new_faculty_vote = FacultyVote(
                        faculty_name=voter.faculty,
                        vote_count=1,
                        candidate_id=candidate.id
                    )
                    db.session.add(new_faculty_vote)

                db.session.commit()

                 # Clear voter details from session after successful vote
                voter_name = session.pop('voter_name', 'Voter') # Get name for thank you message
                session.pop('voter_id', None)
                session.pop('voter_faculty', None)


                flash(f'Terima kasih telah memilih, {voter_name}!', 'success')
                return render_template('thank_you.html') # Create this template
            except Exception as e:
                db.session.rollback()
                flash(f'Terjadi kesalahan saat merekam suara Anda: {str(e)}', 'danger')
                return redirect(url_for('voting_page')) # Stay on voting page on error
        else:
             flash('Percobaan memilih tidak valid. Kandidat tidak valid atau Anda sudah memilih.', 'warning')
             # Clear session data just in case
             session.pop('voter_id', None)
             session.pop('voter_name', None)
             session.pop('voter_faculty', None)
             return redirect(url_for('voter_verification'))

     # GET request: Display candidates
     candidates = Candidate.query.all()
     voter_name = session.get('voter_name', 'Voter')
     voter_faculty = session.get('voter_faculty', 'Unknown')
     voter_student_id = session.get('voter_student_id', 'Unknown')


     return render_template('voting_page.html',
                           candidates=candidates,
                           voter_name=voter_name,
                           voter_faculty=voter_faculty,
                           voter_student_id=voter_student_id) # We'll create this template later


@app.route('/voting_auth', methods=['GET', 'POST'])
def voting_auth():
     settings = VotingSettings.query.first()
     now = datetime.now()

     # --- RESTORED CHECK ---
     # Restore original time checks
     if not settings or not settings.published or \
        (settings.start_time and now < settings.start_time) or \
        (settings.end_time and now > settings.end_time):
         flash('Pemilihan sedang tidak aktif.', 'info')
         return redirect(url_for('index'))

     if request.method == 'POST':
          password = request.form['password']
          if settings and settings.check_voting_password(password):
               session['voting_access_granted'] = True
               flash('Password diterima. Harap verifikasi identitas Anda.', 'success')
               return redirect(url_for('voter_verification'))
          else:
               flash('Password pemilihan salah.', 'danger')
     return render_template('voting_auth.html') # We'll create this template later


@app.route('/voter_verification', methods=['GET', 'POST'])
def voter_verification():
     settings = VotingSettings.query.first()
     now = datetime.now()

     # --- RESTORED CHECK ---
     # Restore original time checks
     if not settings or not settings.published or \
        (settings.start_time and now < settings.start_time) or \
        (settings.end_time and now > settings.end_time):
          flash('Pemilihan sedang tidak aktif.', 'info')
          return redirect(url_for('index'))

     if 'voting_access_granted' not in session:
         flash('Harap masukkan password pemilihan terlebih dahulu.', 'warning')
         return redirect(url_for('voting_auth'))


     if request.method == 'POST':
          search_term = request.form['search_term'].strip()
          voter = Voter.query.filter(
               (Voter.student_id == search_term) | (Voter.name.ilike(f'%{search_term}%'))
          ).first() # Find by ID or Name (case-insensitive for name)


          if voter:
               if voter.has_voted:
                    flash('ID/Nama ini sudah memilih.', 'warning')
               else:
                    # Store voter details in session and proceed to voting page
                    session['voter_id'] = voter.id
                    session['voter_student_id'] = voter.student_id
                    session['voter_name'] = voter.name
                    session['voter_faculty'] = voter.faculty
                    flash(f'Selamat datang, {voter.name}! Silakan berikan suara Anda.', 'success')
                    return redirect(url_for('voting_page'))
          else:
               flash('Pemilih tidak ditemukan atau tidak memenuhi syarat.', 'danger')

     return render_template('voter_verification.html') # Create this template

# --- Monitoring Page Route ---

@app.route('/monitor')
def monitor_page():
    # This page will likely use JavaScript to fetch data periodically
    # Pass initial data for rendering
    candidates = Candidate.query.all()
    faculty_data = {} # Structure: {faculty: {candidate_name: votes}}
    candidate_totals = {c.name: c.votes for c in candidates}
    all_faculties = set(v.faculty for v in Voter.query.all()) # Get all unique faculties

    for faculty in all_faculties:
        faculty_data[faculty] = {}
        for candidate in candidates:
            fv = FacultyVote.query.filter_by(candidate_id=candidate.id, faculty_name=faculty).first()
            faculty_data[faculty][candidate.name] = fv.vote_count if fv else 0


    return render_template('monitor_page.html',
                           candidates=candidates,
                           faculty_data=faculty_data,
                           candidate_totals=candidate_totals,
                           all_faculties=sorted(list(all_faculties))
                           ) # Create this


@app.route('/monitor/data')
def monitor_data():
     # API endpoint for JavaScript to fetch updated data
     candidates = Candidate.query.all()
     faculty_data = {}
     candidate_totals = {c.name: c.votes for c in candidates}
     all_faculties = set(fv.faculty_name for fv in FacultyVote.query.all()) | set(v.faculty for v in Voter.query.all()) # Ensure all faculties are captured


     for faculty in all_faculties:
          faculty_data[faculty] = {}
          for candidate in candidates:
               fv = FacultyVote.query.filter_by(candidate_id=candidate.id, faculty_name=faculty).first()
               faculty_data[faculty][candidate.name] = fv.vote_count if fv else 0


     return {
          "candidate_totals": candidate_totals,
          "faculty_data": faculty_data,
          "all_faculties": sorted(list(all_faculties)),
          "candidate_names": [c.name for c in candidates] # Send candidate names for chart labels
     }


# --- Utility Route to Create Database ---
@app.route('/create_db')
def create_db_route():
     # Check if run in development environment maybe?
     # Or protect with an admin login / specific key in URL?
     # For simplicity now, just allow access, but WARN THIS IS INSECURE FOR PRODUCTION
     try:
          with app.app_context():
               db.create_all()
          return "Database tables created!"
     except Exception as e:
          return f"Error creating database: {str(e)}"


# --- Serve Uploaded Files ---
from flask import send_from_directory

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/admin/delete_candidate/<int:candidate_id>', methods=['POST'])
@login_required
def delete_candidate(candidate_id):
    candidate = Candidate.query.get_or_404(candidate_id)
    try:
        # Optional: Delete associated files (photo, pdf) from the uploads folder
        if candidate.photo_path:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], candidate.photo_path))
            except OSError as e:
                print(f"Error deleting photo file {candidate.photo_path}: {e}") # Log error but continue
        if candidate.vision_mission_path:
             try:
                 os.remove(os.path.join(app.config['UPLOAD_FOLDER'], candidate.vision_mission_path))
             except OSError as e:
                 print(f"Error deleting VM file {candidate.vision_mission_path}: {e}") # Log error but continue

        # FacultyVote entries are deleted automatically due to cascade rule defined in Candidate model

        db.session.delete(candidate)
        db.session.commit()
        flash(f'Kandidat \'{candidate.name}\' berhasil dihapus.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal menghapus kandidat: {str(e)}', 'danger')
    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    # Ensure upload folder exists
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    # Create database tables if they don't exist upon startup
    with app.app_context():
        db.create_all()

        # Check if an admin exists, if not, guide user
        if not Admin.query.first():
             print("*"*50)
             print("No admin user found. Please navigate to /setup_admin in your browser to create one.")
             print("*"*50)


         # Ensure VotingSettings exists
        if not VotingSettings.query.first():
             print("Initializing default voting settings record.")
             default_settings = VotingSettings()
             db.session.add(default_settings)
             db.session.commit()


    app.run(debug=True) # debug=True for development, remove/set to False for production 