import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema(
	{
		username: {
			type: String,
			required: [true, 'A username is required.'],
			minLength: [3, 'Your username must be at least 3 characters in length.'],
			trim: true,
			lowercase: true,
			unique: true,
			validate: {
				validator: value => !value || /^[a-zA-Z0-9]+$/.test(value),
				message: 'Your username can only contain letters and numbers.',
			},
		},
		email: {
			type: String,
			required: [true, 'An email is required.'],
			match: [/.+\@.+\..+/, 'Please enter a valid email address.'],
			unique: true,
			lowercase: true,
			trim: true,
		},
		password: {
			type: String,
			required: [true, 'A password is required.'],
			minLength: [8, 'Your password must be at least 8 characters long.'],
			trim: true,
			validate: {
				validator: value => {
					const hasUpperCase = /[A-Z]/.test(value);
					const hasLowerCase = /[a-z]/.test(value);
					const hasNumber = /[0-9]/.test(value);
					const hasSpecialChar = /[!@#$%^&*()_+{}\[\]:;<>,.?~\\/-]/.test(value);
					return hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar;
				},
				message:
					'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
			},
		},
	},
	{
		timestamps: true,
	},
);

userSchema.index({ username: 1, email: 1 });

// Match user entered password to hashed password in DB
userSchema.methods.matchPassword = async function (enteredPassword) {
	return await bcrypt.compare(enteredPassword, this.password);
};

// Encrypt password using bcrypt
userSchema.pre('save', async function (next) {
	if (!this.isModified('password')) {
		next();
	}
	const salt = await bcrypt.genSalt(10);
	this.password = await bcrypt.hash(this.password, salt);
});

const User = mongoose.model('User', userSchema);

export default User;
