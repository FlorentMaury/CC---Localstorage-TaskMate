import { useEffect, useState, useContext } from 'react';
import { AuthContext } from './AuthContext';
import Login from './components/Login';
import Register from './components/Register';
import { Header } from './components/Header';
import { AddTask } from './components/AddTask';
import { ShowTask } from './components/ShowTask';
import { getAllTasks, addTask, updateTask, deleteTask } from "./db";
import './App.css';

function App() {
  const [taskList, setTaskList] = useState(() => {
    const savedTasks = sessionStorage.getItem("tasklist");
    return savedTasks ? JSON.parse(savedTasks) : [];
  });
  const [task, setTask] = useState({});
  const [isRegister, setIsRegister] = useState(false);
  const { user } = useContext(AuthContext);

  useEffect(() => {
    const fetchTasks = async () => {
      if (user) {
        const tasks = await getAllTasks();
        const userTasks = tasks.filter(
          (task) => task.username === user.username
        );
        setTaskList(userTasks);
      }
    };
    fetchTasks();
  }, [user]);

  useEffect(() => {
    sessionStorage.setItem("tasklist", JSON.stringify(taskList));
    const saveTasks = async () => {
      await Promise.all(taskList.map((task) => updateTask(task)));
    };
    saveTasks();
  }, [taskList]);

  const handleAddTask = async (newTask) => {
    const id = await addTask(newTask);
    setTaskList([...taskList, { ...newTask, id }]);
  };

  const handleDeleteTask = async (id) => {
    await deleteTask(id);
    const updateTaskList = taskList.filter((todo) => todo.id !== id);
    setTaskList(updateTaskList);
  };

  const handleUpdateTask = async (taskToUpdate) => {
    await Promise.all(taskToUpdate.map((task) => updateTask(task)));
    setTaskList(taskToUpdate);
    setTask({});
  };

  const toggleForm = () => {
    setIsRegister(!isRegister);
  };

  return (
    <>
      {user ? (
        <div className="App">
          <Header />
          <AddTask
            taskList={taskList}
            setTaskList={handleAddTask}
            task={task}
            setTask={setTask}
            updateTask={handleUpdateTask}
          />
          <ShowTask
            taskList={taskList}
            setTaskList={setTaskList}
            task={task}
            setTask={setTask}
            handleDeleteTask={handleDeleteTask}
          />
        </div>
      ) : (
        <div>
          <Header />
          {isRegister ? (
            <Register toggleForm={toggleForm} />
          ) : (
            <Login toggleForm={toggleForm} />
          )}
        </div>
      )}
    </>
  );
}

export default App;
