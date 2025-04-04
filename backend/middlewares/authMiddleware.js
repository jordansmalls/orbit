import jwt from 'jsonwebtoken';
import User from '../models/userModel.js';

const protect = async (req, res, next) => {
	let token;

	token = req.cookies.jwt;

	if (token) {
		try {
			const decoded = jwt.verify(token, process.env.JWT_SECRET);

			req.user = await User.findById(decoded.userId).select('-password');

			next();
		} catch (error) {
			console.error(error);
			return res.status(401).json({ message: 'Not authorized, token failed' });
		}
	} else {
		return res.status(401).json({ message: 'Not authorized, no token' });
	}
};

export { protect };
