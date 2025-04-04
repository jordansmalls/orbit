import {
	createUser,
	loginUser,
	logoutUser,
	updateUsername,
	updateEmail,
	updatePassword,
	getUserProfile,
	deleteUser,
} from '../controllers/userController.js';
import express from 'express';
import { protect } from '../middlewares/authMiddleware.js';

const router = express.Router();

// Public Routes

router.post('/', createUser);
router.post('/login', loginUser);
router.post('/logout', logoutUser);

// Private Routes

router.put('/username', protect, updateUsername);
router.put('/email', protect, updateEmail);
router.put('/password', protect, updatePassword);
router.get('/me', protect, getUserProfile);
router.delete('/:id', protect, deleteUser);

export default router;
