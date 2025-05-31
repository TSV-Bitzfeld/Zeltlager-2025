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
    initializePersonFormHandling();
    initializeFormSubmission();
    handleFlashMessages();
    console.log('Script initialized');
});

// Person form handling
function initializePersonFormHandling() {
    const addButton = document.querySelector(SELECTORS.ADD_PERSON_BUTTON);
    const container = document.querySelector(SELECTORS.PERSONS_CONTAINER);

    if (!addButton || !container) {
        console.error('Add button or container not found');
        return;
    }

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
                    if (!/^\+?[0-9\s-]+$/.test(field.value.trim())) {
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
    handleFlashMessages();
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
    if (!form) {
        console.error('Registration form not found');
        return;
    }
    form.addEventListener('submit', handleFormSubmit);
    console.log('Form submission initialized');
}

async function handleFormSubmit(event) {
    event.preventDefault();
    console.log('Form submitted');
    
    if (!validateForm()) {
        console.log('Form validation failed');
        return;
    }

    try {
        const formData = collectFormData();
        if (!formData) {
            console.log('Form data collection failed');
            return;
        }

        console.log('Submitting form data:', formData);
        const response = await submitForm(formData);
        handleSubmissionResponse(response);
    } catch (error) {
        console.error('Submission error:', error);
        addFlashMessage(`❌ Fehler beim Absenden: ${error.message}`, 'error');
    }
}

function collectFormData() {
    const persons = collectPersonsData();
    
    console.log('Collected persons:', persons);
    
    if (persons.length === 0) {
        addFlashMessage('❌ Bitte füllen Sie alle Felder für mindestens ein Kind aus.', 'error');
        return null;
    }

    const csrfToken = document.querySelector(SELECTORS.CSRF_TOKEN)?.value?.trim();
    if (!csrfToken) {
        addFlashMessage('❌ CSRF-Token fehlt. Bitte laden Sie die Seite neu.', 'error');
        return null;
    }

    const cakeDonation = document.querySelector('select[name="cake_donation"]')?.value;
    const helpOrganisation = document.querySelector('select[name="help_organisation"]')?.value;

    if (!cakeDonation) {
        addFlashMessage('❌ Bitte wählen Sie eine Kuchenspende-Option aus.', 'error');
        return null;
    }

    if (!helpOrganisation) {
        addFlashMessage('❌ Bitte wählen Sie eine Auf-/Abbau-Option aus.', 'error');
        return null;
    }

    const formData = {
        csrf_token: csrfToken,
        persons,
        contact_firstname: document.getElementById('contact_firstname')?.value?.trim() || '',
        contact_lastname: document.getElementById('contact_lastname')?.value?.trim() || '',
        contact_birthdate: document.getElementById('contact_birthdate')?.value || '',
        phone_number: document.getElementById('phone_number')?.value?.trim() || '',
        email: document.getElementById('email')?.value?.trim() || '',
        cake_donation: cakeDonation,
        help_organisation: helpOrganisation
    };
    
    console.log('Form data to submit:', formData);
    return formData;
}

function validatePersonData(personData) {
    if (!personData.person_firstname || !personData.person_lastname || 
        !personData.birthdate || !personData.club_membership) {
        console.log('Person data incomplete:', personData);
        return false;
    }
    
    // Altersvalidierung
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
    
    // Sammle Daten aus allen Person-Formularen (einschließlich dem ersten)
    // Erweiterte Selektion um sicherzustellen, dass das erste Formular erfasst wird
    const personForms = document.querySelectorAll('.person-form, #person_1, [id^="person_"]');
    
    console.log('Found person forms:', personForms.length);
    
    personForms.forEach((form, index) => {
        console.log(`Processing form ${index + 1}:`, form);
        
        const personData = {
            person_firstname: form.querySelector('input[name^="person_firstname"], input[name*="person_firstname"]')?.value?.trim() || '',
            person_lastname: form.querySelector('input[name^="person_lastname"], input[name*="person_lastname"]')?.value?.trim() || '',
            birthdate: form.querySelector('input[name^="birthdate"], input[name*="birthdate"]')?.value || '',
            club_membership: form.querySelector('select[name^="club_membership"], select[name*="club_membership"]')?.value || ''
        };

        console.log(`Person data ${index + 1}:`, personData);

        // Nur hinzufügen wenn alle Felder ausgefüllt sind
        if (personData.person_firstname && personData.person_lastname && 
            personData.birthdate && personData.club_membership) {
            
            if (validatePersonData(personData)) {
                persons.push(personData);
                console.log(`Added person ${index + 1} to list`);
            }
        } else {
            console.log(`Person ${index + 1} incomplete, skipping`);
        }
    });
    
    console.log('Final persons array:', persons);
    return persons;
}

async function submitForm(formData) {
    console.log('Sending request to server...');
    
    // Get CSRF token for headers
    const csrfToken = formData.csrf_token;
    
    const response = await fetch('/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
            'X-CSRFToken': csrfToken  // Add CSRF token to headers
        },
        credentials: 'same-origin',
        body: JSON.stringify(formData)
    });

    console.log('Response status:', response.status);
    console.log('Response headers:', response.headers);

    if (!response.ok) {
        const errorText = await response.text();
        console.error('Server error:', errorText);
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    console.log('Server response:', data);
    
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
    console.log('Handling response:', data);
    
    if (data.success) {
        addFlashMessage('✅ Anmeldung erfolgreich! Sie werden weitergeleitet.', 'success');
        setTimeout(() => {
            const redirectUrl = data.redirect || '/confirmation';
            console.log('Redirecting to:', redirectUrl);
            window.location.href = redirectUrl;
        }, 2000);
    } else {
        addFlashMessage('❌ Fehler bei der Anmeldung: ' + (data.error || 'Unbekannter Fehler'), 'error');
    }
}