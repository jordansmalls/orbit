import express from 'express';
import dotenv from 'dotenv';
dotenv.config();
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import userRoutes from './routes/userRoutes.js';

const app = express();
const PORT = process.env.PORT || 9999;

app.use(morgan('dev'));
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Routes
app.use('/api/users', userRoutes);

app.get('/', (req, res) => {
	res.send('This is a test from the express backend.');
});

app.get('/test', (req, res) => {
	res.json({ message: 'This is a test.' });
});

app.listen(PORT, () => console.log(`Server is running on port ${PORT}.`));
