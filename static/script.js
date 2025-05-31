// Constants and DOM element cache
const SELECTORS = {
    ADD_PERSON_BUTTON: '#add-person-button',
    PERSONS_CONTAINER: '#persons-container',
    REGISTRATION_FORM: '#registrationForm',
    CSRF_TOKEN: 'input[name="csrf_token"]',
    PERSON_FORM: '.person-form'
};

// Main initialization function
document.addEventListener('DOMContentLoaded', () => {
    initializePaymentControls();
    initializePersonFormHandling();
    initializeFormSubmission();
    handleFlashMessages();
});

// Payment controls initialization
function initializePaymentControls() {
    console.log('Payment controls initialized - Bank transfer only');
}

// Person form handling
function initializePersonFormHandling() {
    const addButton = document.querySelector(SELECTORS.ADD_PERSON_BUTTON);
    const container = document.querySelector(SELECTORS.PERSONS_CONTAINER);

    if (!addButton || !container) return;

    addButton.addEventListener('click', () => addPersonForm(container));
    container.addEventListener('click', handlePersonFormRemoval);
}

function validateForm() {
    let isValid = true;
    const requiredFields = document.querySelectorAll('[required]');
    
    // Clear previous error messages
    document.querySelectorAll('.validation-error').forEach(el => el.remove());
    document.querySelectorAll('.error-field').forEach(el => el.classList.remove('error-field'));
    
    requiredFields.forEach(field => {
        let errorMessage = '';
        
        // Validate based on input type and specific conditions
        if (!field.value.trim()) {
            errorMessage = 'Dieses Feld ist erforderlich';
        } else {
            switch(field.type) {
                case 'text':
                    if (field.name.includes('person_firstname') || field.name.includes('person_lastname') || 
                        field.name.includes('contact_firstname') || field.name.includes('contact_lastname')) {
                        if (field.value.trim().length < 2) {
                            errorMessage = 'Mindestens 2 Zeichen erforderlich';
                        } else if (!/^[A-Za-zÄÖÜäöüß\s-]+$/.test(field.value.trim())) {
                            errorMessage = 'Nur Buchstaben und Bindestriche erlaubt';
                        }
                    }
                    break;
                case 'email':
                    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(field.value.trim())) {
                        errorMessage = 'Ungültige E-Mail-Adresse';
                    }
                    break;
                case 'tel':
                    if (!/^(?:\d{4}[- ]?\d{7}|\d{4}[- ]?\d{8}|\d{5}[- ]?\d{6}|\d{5}[- ]?\d{7})$/.test(field.value.trim())) {
                        errorMessage = 'Ungültiges Telefonnummerformat';
                    }
                    break;
                case 'date':
                    const selectedDate = new Date(field.value);
                    const currentDate = new Date();
                    if (selectedDate > currentDate) {
                        errorMessage = 'Geburtsdatum kann nicht in der Zukunft liegen';
                    }
                    break;
                case 'select-one':
                    if (field.value === '' || field.value === field.querySelector('option').value) {
                        errorMessage = 'Bitte eine Option auswählen';
                    }
                    if (field.name === 'cake_donation' && field.value === '') {
                        errorMessage = 'Bitte wählen Sie eine Kuchenspende-Option aus';
                    }
                    if (field.name === 'help_organisation' && field.value === '') {
                        errorMessage = 'Bitte wählen Sie eine Auf-/Abbau-Option aus';
                    }
                    break;
            }
        }
        
        // If there's an error, highlight and show message
        if (errorMessage) {
            isValid = false;
            const errorDiv = document.createElement('div');
            errorDiv.classList.add('validation-error');
            errorDiv.textContent = errorMessage;
            field.parentNode.insertBefore(errorDiv, field.nextSibling);
            field.classList.add('error-field');
            
            // Scroll to first error
            if (isValid === false) {
                field.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        }
    });
    
    // Show overall error message if form is invalid
    if (!isValid) {
        addFlashMessage('❌ Bitte überprüfen Sie Ihre Eingaben.', 'error');
    }
    
    return isValid;
}

function handleFlashMessages() {
    document.querySelectorAll('.flash-message:not([data-handled])').forEach(message => {
        message.dataset.handled = 'true';
        
        // Style for centered, boxed messages
        message.style.position = 'fixed';
        message.style.top = '50%';
        message.style.left = '50%';
        message.style.transform = 'translate(-50%, -50%)';
        message.style.backgroundColor = 'rgba(0, 0, 0, 1)';
        message.style.color = 'white';
        message.style.padding = '15px 30px';
        message.style.borderRadius = '8px';
        message.style.zIndex = '1000';
        message.style.textAlign = 'center';
        
        // Fade out and remove after 3 seconds
        setTimeout(() => {
            message.style.transition = 'opacity 0.5s';
            message.style.opacity = '0';
            setTimeout(() => message.remove(), 500);
        }, 3000);
    });
}

function addFlashMessage(message, type) {
    const flashMsg = document.createElement('div');
    flashMsg.classList.add('flash-message', type);
    flashMsg.textContent = message;
    document.body.appendChild(flashMsg);
    handleFlashMessages(flashMsg);
}

function addPersonForm(container) {
    const personCount = document.querySelectorAll(SELECTORS.PERSON_FORM).length + 1;
    const personForm = createPersonFormElement(personCount);
    container.appendChild(personForm);
}

function createPersonFormElement(personCount) {
    const div = document.createElement('div');
    div.classList.add('person-form');
    div.setAttribute('data-person-id', personCount);
    div.innerHTML = getPersonFormTemplate(personCount);
    return div;
}

function getPersonFormTemplate(personCount) {
    return `
        <hr class="person-contact-divider">
        <h3>Kind ${personCount}</h3>
        <label>Name des Kindes *</label>
        <div class="name-fields">
            <input type="text" name="person_firstname_${personCount}" placeholder="Vorname" required>
            <input type="text" name="person_lastname_${personCount}" placeholder="Nachname" required>
        </div>
        <label>Geburtsdatum des Kindes *</label>
        <input type="date" name="birthdate_${personCount}" required>
        <label>Vereinsmitgliedschaft *</label>
        <select name="club_membership_${personCount}" required>
            <option value="">Verein auswählen</option>
            <option value="TSV Bitzfeld 1922 e.V.">TSV Bitzfeld 1922 e.V.</option>
            <option value="TSV Schwabbach 1947 e.V.">TSV Schwabbach 1947 e.V.</option>
        </select>
        <div class="change-person-button-container">
            <button type="button" class="change-person-button">Dieses Kind entfernen</button>
        </div>
    `;
}

function handlePersonFormRemoval(event) {
    if (!event.target.classList.contains('change-person-button')) return;
    
    const personForm = event.target.closest(SELECTORS.PERSON_FORM);
    if (personForm) {
        personForm.remove();
        updatePersonNumbers();
    }
}

function updatePersonNumbers() {
    document.querySelectorAll(SELECTORS.PERSON_FORM).forEach((form, index) => {
        const newIndex = index + 1;
        updatePersonFormIndices(form, newIndex);
    });
}

function updatePersonFormIndices(form, newIndex) {
    form.querySelector('h3').textContent = `Kind ${newIndex}`;
    form.setAttribute('data-person-id', newIndex);

    const inputs = {
        'person_firstname': 'input[name^="person_firstname"]',
        'person_lastname': 'input[name^="person_lastname"]',
        'birthdate': 'input[name^="birthdate"]',
        'club_membership': 'select[name^="club_membership"]'
    };

    Object.entries(inputs).forEach(([key, selector]) => {
        const element = form.querySelector(selector);
        if (element) element.setAttribute('name', `${key}_${newIndex}`);
    });
}

// Form submission handling
function initializeFormSubmission() {
    const form = document.querySelector(SELECTORS.REGISTRATION_FORM);
    if (!form) return;
    form.addEventListener('submit', handleFormSubmit);
}

async function handleFormSubmit(event) {
    event.preventDefault();
    
    if (!validateForm()) {
        return;
    }

    try {
        const formData = collectFormData();
        if (!formData) return;

        const response = await submitForm(formData);
        handleSubmissionResponse(response);
    } catch (error) {
        console.error('Submission error:', error);
        addFlashMessage(`❌Fehler beim Absenden: ${error.message}`, 'error');
    }
}

function collectFormData() {
    const persons = collectPersonsData();
    if (persons.length === 0) {
        addFlashMessage('❌Bitte fügen Sie mindestens eine Person hinzu.', 'error');
        return null;
    }

    const csrfToken = document.querySelector(SELECTORS.CSRF_TOKEN)?.value?.trim();
    if (!csrfToken) {
        addFlashMessage('❌CSRF-Token fehlt. Bitte laden Sie die Seite neu.', 'error');
        return null;
    }

    const cakeDonation = document.querySelector('select[name="cake_donation"]')?.value;
    const helpOrganisation = document.querySelector('select[name="help_organisation"]')?.value;

    if (!cakeDonation) {
        addFlashMessage('❌Bitte wählen Sie eine Kuchenspende-Option aus.', 'error');
        return null;
    }

    if (!helpOrganisation) {
        addFlashMessage('❌Bitte wählen Sie eine Auf-/Abbau-Option aus.', 'error');
        return null;
    }

    return {
        csrf_token: csrfToken,
        persons,
        contact_firstname: document.getElementById('contact_firstname').value,
        contact_lastname: document.getElementById('contact_lastname').value,
        contact_birthdate: document.getElementById('contact_birthdate').value,
        phone_number: document.getElementById('phone_number').value,
        email: document.getElementById('email').value,
        cake_donation: cakeDonation,
        help_organisation: helpOrganisation
    };
}

function validatePersonData(personData) {
    if (!personData.person_firstname || !personData.person_lastname || 
        !personData.birthdate || !personData.club_membership) {
        return false;
    }
    
    // ✨ Altersvalidierung auch im Frontend
    const birthDate = new Date(personData.birthdate);
    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDiff = today.getMonth() - birthDate.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
        age--;
    }
    
    if (age < 6 || age > 11) {
        addFlashMessage(`❌ Kind ist ${age} Jahre alt. Zeltlager ist für 1.-5. Klasse (6-11 Jahre).`, 'error');
        return false;
    }
    
    return true;
}

function collectPersonsData() {
    const persons = [];
    document.querySelectorAll(SELECTORS.PERSON_FORM).forEach(form => {
        const personData = {
            person_firstname: form.querySelector('input[name^="person_firstname"]')?.value?.trim() || '',
            person_lastname: form.querySelector('input[name^="person_lastname"]')?.value?.trim() || '',
            birthdate: form.querySelector('input[name^="birthdate"]')?.value || '',
            club_membership: form.querySelector('select[name^="club_membership"]')?.value || ''
        };

        if (validatePersonData(personData)) {
            persons.push(personData);
        }
    });
    return persons;
}

async function submitForm(formData) {
    const csrfToken = formData.csrf_token;
    const response = await fetch('/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken,
            'X-Requested-With': 'XMLHttpRequest'  // Add this line
        },
        credentials: 'same-origin',
        body: JSON.stringify(formData)
    });

    const data = await response.json();
    if (data.errors) {
        Object.entries(data.errors).forEach(([field, messages]) => {
            const input = document.querySelector(`[name="${field}"]`);
            if (input) {
                const errorDiv = document.createElement('div');
                errorDiv.classList.add('validation-error');
                errorDiv.textContent = messages[0];
                input.parentNode.insertBefore(errorDiv, input.nextSibling);
                input.classList.add('error-field');
            }
        });
        return { success: false };
    }
    return data;
}

function handleSubmissionResponse(data) {
    if (data.success) {
        addFlashMessage('✅ Anmeldung erfolgreich! Sie werden weitergeleitet.', 'success');
        setTimeout(() => window.location.href = '/confirmation', 3000);
    } else {
        addFlashMessage('❌ Fehler bei der Anmeldung: ' + data.error, 'error');
    }
}

// Handle delete confirmations
const deleteButtons = document.querySelectorAll('.delete-button');
deleteButtons.forEach(button => {
    button.addEventListener('click', function(e) {
        e.preventDefault();
        const confirmDiv = document.createElement('div');
        confirmDiv.classList.add('flash-message', 'warning');
        confirmDiv.innerHTML = `
            <p>Möchten Sie diesen Eintrag wirklich löschen?</p>
            <button onclick="this.parentElement.remove();">Abbrechen</button>
            <button onclick="this.closest('form').submit();">Löschen</button>
        `;
        document.body.appendChild(confirmDiv);
    });
});