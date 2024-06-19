import { useContext } from "react";
import { AuthContext } from "../AuthContext";

export const AddTask = ({
    taskList,
    setTaskList,
    task,
    setTask,
    updateTask,
}) => {
    const { user } = useContext(AuthContext);
    const handleSubmit = (e) => {
        e.preventDefault();

        if (task.id) {
            const date = new Date();
            const updateTaskList = taskList.map((todo) =>
                todo.id === task.id
                    ? {
                        id: task.id,
                        username: user.username,
                        name: task.name,
                        time: `${date.toLocaleTimeString()} ${date.toLocaleTimeString()}`,
                    }
                    : todo
            );
            updateTask(updateTaskList);
        } else {
            const date = new Date();
            const newTask = {
                id: date.getTime(),
                username: user.username,
                name: e.target.task.value,
                time: `${date.toLocaleTimeString()} ${date.toLocaleTimeString()}`,
            };
            setTaskList(newTask);
            setTask({});
        }
    };

    return (
        <section className="addTask">
            <form onSubmit={handleSubmit}>
                <input
                    type="text"
                    name="task"
                    value={task.name || ""}
                    autoComplete="off"
                    placeholder="Add task"
                    maxLength="25"
                    onChange={(e) => setTask({ ...task, name: e.target.value })}
                />
                <button type="submit">{task.id ? "Update" : "Add"}</button>
            </form>
        </section>
    );
};