export const ShowTask = ({
    taskList = [],
    setTaskList,
    task,
    setTask,
    handleDeleteTask,
}) => {
    const handleEdit = (id) => {
        const selectedTask = taskList.find((todo) => todo.id === id);
        setTask(selectedTask);
    };

    const handleDelete = (id) => {
        handleDeleteTask(id);
    };

    return (
        <section className="showTask">
            <div className="head">
                <div>
                    <span className="title">To Do</span>
                    <span className="count">{taskList.length}</span>
                </div>
                <button onClick={() => setTaskList([])} className="clearAll">
                    {" "}
                    Clear All
                </button>
            </div>
            <ul>
                {taskList.map((todo) => (
                    <li key={todo.id}>
                        <p>
                            <span className="name">{todo.name}</span>
                            <span className="time">{todo.time}</span>
                        </p>
                        <i
                            onClick={() => handleEdit(todo.id)}
                            className="bi bi-pencil-square"
                        ></i>
                        <i
                            onClick={() => handleDelete(todo.id)}
                            className="bi bi-trash"
                        ></i>
                    </li>
                ))}
            </ul>
        </section>
    );
};