import User from '../models/userModel.js';
import generateToken from '../utils/generateToken.js';

// @desc    Create user
// @route   POST /api/users
// @access  Public

export const createUser = async (req, res) => {
	const { username, email, password } = req.body;

	try {
		const usernameExists = await User.findOne({ username });
		const emailExists = await User.findOne({ email });

		if (usernameExists) {
			res.status(409).json({ message: 'Username is already taken.' });
		}

		if (emailExists) {
			res.status(409).json({ message: 'Email address is already taken.' });
		}

		const user = await User.create({
			username,
			email,
			password,
		});

		generateToken(res, user._id);

		res.status(201).json({
			_id: user._id,
			username: user.username,
			email: user.email,
		});
	} catch (error) {
		console.error('Error creating user:', error);
		res.status(500).json({ message: 'Internal server error.' });
	}
};

// @desc    Login user
// @route   POST /api/users/login
// @access  Public

export const loginUser = async (req, res) => {
	const { username, password } = req.body;

	const user = await User.findOne({ username });

	if (user && (await user.matchPassword(password))) {
		generateToken(res, user._id);

		res.json({
			_id: user._id,
			username: user.username,
			email: user.email,
		});
	} else {
		res.status(401).json({ message: 'Invalid username or password.' });
	}
};

// @desc    Logout user
// @route   POST /api/users/logout
// @access  Public

export const logoutUser = (req, res) => {
	try {
		res.cookie('jwt', '', {
			httpOnly: true,
			expires: new Date(0),
		});
		res.status(200).json({ message: 'Logged out successfully.' });
	} catch (error) {
		console.error('There was an error', error);
		res.status(500).json({ message: 'There was a server error, please try again soon.' });
	}
};

// @desc    Update username
// @route   PUT /api/users/username
// @access  Private

export const updateUsername = async (req, res) => {
	const { username } = req.body;

	try {
		if (!req.user) {
			res.status(401).json({ message: 'Not authorized.' });
		}

		const usernameExists = await User.findOne({ username });

		if (usernameExists && usernameExists._id.toString() !== req.user._id.toString()) {
			res.status(409).json({ message: 'Username is already taken.' });
		}

		const updatedUser = await User.findByIdAndUpdate(req.user._id, { username }, { new: true });

		if (updatedUser) {
			res.status(200).json({
				_id: updatedUser._id,
				username: updatedUser.username,
				email: updatedUser.email,
			});
		} else {
			res.status(404).json({ message: 'User not found.' });
		}
	} catch (error) {
		console.error('Error updating username:', error);
		res.status(500).json({ message: 'Internal server error.' });
	}
};

// @desc    Update email
// @route   PUT /api/users/email
// @access  Private

export const updateEmail = async (req, res) => {
	const { email } = req.body;

	try {
		if (!req.user) {
			return res.status(401).json({ message: 'Not authorized.' });
		}

		const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

		if (!emailRegex.test(email)) {
			res.status(400).json({ message: 'Invalid email format.' });
		}

		const emailExists = await User.findOne({ email });

		if (emailExists && emailExists._id.toString() !== req.user._id.toString()) {
			res.status(409).json({ message: 'Email is already associated with an account.' });
		}

		const updatedUser = await User.findByIdAndUpdate(req.user._id, { email }, { new: true });

		if (updatedUser) {
			res.status(200).json({
				_id: updatedUser._id,
				email: updatedUser.email,
				username: updatedUser.username,
			});
		} else {
			res.status(404).json({ message: 'User not found.' });
		}
	} catch (error) {
		console.error('Error updating email:', error);
		res.status(500).json({ message: 'Internal server error.' });
	}
};

// @desc    Update password
// @route   PUT /api/users/password
// @access  Private

export const updatePassword = async (req, res) => {
	const { oldPassword, newPassword } = req.body;

	try {
		if (!req.user) {
			return res.status(401).json({ message: 'Not authorized.' });
		}

		const user = await User.findById(req.user._id).select('+password');

		if (!user) {
			return res.status(404).json({ message: 'User not found.' });
		}

		const passwordMatch = await bcrypt.compare(oldPassword, user.password);

		if (!passwordMatch) {
			return res.status(401).json({ message: 'Invalid old password.' });
		}

		user.password = newPassword;
		await user.save();

		res.status(200).json({ message: 'Password updated successfully.' });
	} catch (error) {
		console.error('Error updating password:', error);
		res.status(500).json({ message: 'Internal server error.' });
	}
};

// @desc    Get user profile
// @route   GET /api/users/me
// @access  Private

export const getUserProfile = async (req, res) => {
	try {
		if (!req.user) {
			return res.status(401).json({ message: 'Not authorized.' });
		}

		const user = await User.findById(req.user._id).select('-password');

		if (user) {
			res.status(200).json(user);
		} else {
			res.status(404).json({ message: 'User not found.' });
		}
	} catch (error) {
		console.error('Error getting user profile:', error);
		res.status(500).json({ message: 'Internal server error.' });
	}
};

// @desc    Delete user
// @route   DELETE /api/users/:id
// @access  Private

export const deleteUser = async (req, res) => {
	try {
		if (!req.user) {
			res.status(401).json({ message: 'Not authorized.' });
		}

		const userToDelete = await User.findById(req.params.id);

		if (!userToDelete) {
			res.status(404).json({ message: 'User not found.' });
		}

		// Only allow the user to delete their own account.
		if (userToDelete._id.toString() !== req.user._id.toString()) {
			res.status(403).json({ message: 'Forbidden.' });
		}

		await User.findByIdAndDelete(req.params.id);

		res.status(200).json({ message: 'User deleted successfully.' });
	} catch (error) {
		console.error('Error deleting user:', error);
		res.status(500).json({ message: 'Internal server error.' });
	}
};
