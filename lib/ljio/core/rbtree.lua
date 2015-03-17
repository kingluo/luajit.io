-- Copyright (C) Jinhua Luo

local RED = 1
local BLACK = 0

local rbtree_mt = {__index={}}

local function rbtree_left_rotate(tree, sentinel, node)
    local temp = node.right
    node.right = temp.left

    if (temp.left ~= sentinel) then
        temp.left.parent = node
    end

    temp.parent = node.parent

    if (node == tree.root) then
        tree.root = temp
    elseif (node == node.parent.left) then
        node.parent.left = temp
    else
        node.parent.right = temp
    end

    temp.left = node
    node.parent = temp
end

local function rbtree_right_rotate(tree, sentinel, node)
    local temp = node.left
    node.left = temp.right

    if (temp.right ~= sentinel) then
        temp.right.parent = node
    end

    temp.parent = node.parent

    if (node == tree.root) then
        tree.root = temp
    elseif (node == node.parent.right) then
        node.parent.right = temp
    else
        node.parent.left = temp
    end

    temp.right = node
    node.parent = temp
end

local function insert_value(tree, temp, node, sentinel)
    while true do
        if tree.compare_fn(node, temp) then
			if temp.left == sentinel then
				temp.left = node
				break
			else
				temp = temp.left
			end
		else
			if temp.right == sentinel then
				temp.right = node
				break
			else
				temp = temp.right
			end
		end
    end

    node.parent = temp
    node.left = sentinel
    node.right = sentinel
    node.color = RED
end

local function builtin_compare(a,b)
	return (a < b)
end

local function rbtree_new(compare_fn)
	local tree = {}
	tree.color = BLACK
    tree.left = tree
    tree.right = tree
	tree.root = tree
	tree.sentinel = tree
	tree.compare_fn = compare_fn or builtin_compare
	tree.n_node = 0
	return setmetatable(tree, rbtree_mt)
end

function rbtree_mt.__index.size(tree)
	return tree.n_node
end

function rbtree_mt.__index.min(tree, node)
	node = node or tree.root
    while (node.left ~= tree.sentinel) do
        node = node.left
    end
    return node
end

function rbtree_mt.__index.find(tree, key)
	local temp = tree.root
    while temp ~= tree.sentinel do
        if tree.compare_fn(key, temp) then
			temp = temp.left
		elseif tree.compare_fn(temp, key) then
			temp = temp.right
		else
			return temp
		end
    end
end

function rbtree_mt.__index.insert(tree, node)
	tree.n_node = tree.n_node + 1
    local root = tree.root
    local sentinel = tree.sentinel

    if (root == sentinel) then
        node.parent = nil
        node.left = sentinel
        node.right = sentinel
        node.color = BLACK
        tree.root = node
        return
    end

    insert_value(tree, root, node, sentinel)

    while (node ~= root and node.parent.color == RED) do
        if (node.parent == node.parent.parent.left) then
            local temp = node.parent.parent.right

            if temp.color == RED then
                node.parent.color = BLACK
                temp.color = BLACK
                node.parent.parent.color = RED
                node = node.parent.parent
            else
                if (node == node.parent.right) then
                    node = node.parent
                    rbtree_left_rotate(tree, sentinel, node)
                end

                node.parent.color = BLACK
                node.parent.parent.color = RED
                rbtree_right_rotate(tree, sentinel, node.parent.parent)
            end
        else
            local temp = node.parent.parent.left

            if temp.color == RED then
                node.parent.color = BLACK
                temp.color = BLACK
                node.parent.parent.color = RED
                node = node.parent.parent
            else
                if (node == node.parent.left) then
                    node = node.parent
                    rbtree_right_rotate(tree, sentinel, node)
                end

                node.parent.color = BLACK
                node.parent.parent.color = RED
                rbtree_left_rotate(tree, sentinel, node.parent.parent)
            end
        end
    end

    root.color = BLACK
end

function rbtree_mt.__index.delete(tree, node)
	assert(node.left and node.right)
	tree.n_node = tree.n_node - 1

    local sentinel = tree.sentinel
	local subst, temp

    if (node.left == sentinel) then
        temp = node.right
        subst = node
    elseif (node.right == sentinel) then
        temp = node.left
        subst = node
    else
        subst = tree:min(node.right)
        if (subst.left ~= sentinel) then
            temp = subst.left
        else
            temp = subst.right
        end
    end

    if (subst == tree.root) then
        tree.root = temp
        temp.color = BLACK

        node.left = nil
        node.right = nil
        node.parent = nil

        return
    end

    local red = (subst.color == RED)

    if (subst == subst.parent.left) then
        subst.parent.left = temp
    else
        subst.parent.right = temp
    end

    if (subst == node) then
        temp.parent = subst.parent
    else
        if (subst.parent == node) then
            temp.parent = subst
        else
            temp.parent = subst.parent
        end

        subst.left = node.left
        subst.right = node.right
        subst.parent = node.parent
        subst.color = node.color

        if (node == tree.root) then
            tree.root = subst
        else
            if (node == node.parent.left) then
                node.parent.left = subst
            else
                node.parent.right = subst
            end
        end

        if (subst.left ~= sentinel) then
            subst.left.parent = subst
        end

        if (subst.right ~= sentinel) then
            subst.right.parent = subst
        end
    end

    node.left = nil
    node.right = nil
    node.parent = nil

    if (red) then
        return
    end

    while (temp ~= tree.root and temp.color == BLACK) do
        if (temp == temp.parent.left) then
            local w = temp.parent.right

            if w.color == RED then
                w.color = BLACK
                temp.parent.color = RED
                rbtree_left_rotate(tree, sentinel, temp.parent)
                w = temp.parent.right
            end

            if w.left.color == BLACK and w.right.color == BLACK then
                w.color = RED
                temp = temp.parent
            else
                if w.right.color == BLACK then
                    w.left.color = BLACK
                    w.color = RED
                    rbtree_right_rotate(tree, sentinel, w)
                    w = temp.parent.right
                end

				w.color = temp.parent.color
                temp.parent.color = BLACK
                w.right.color = BLACK
                rbtree_left_rotate(tree, sentinel, temp.parent)
                temp = tree.root
            end
        else
            local w = temp.parent.left

            if w.color == RED then
                w.color = BLACK
                temp.parent.color = RED
                rbtree_right_rotate(tree, sentinel, temp.parent)
                w = temp.parent.left
            end

            if w.left.color == BLACK and w.right.color == BLACK then
                w.color = RED
                temp = temp.parent
            else
                if w.left.color == BLACK then
                    w.right.color = BLACK
                    w.color = RED
                    rbtree_left_rotate(tree, sentinel, w)
                    w = temp.parent.left
                end

				w.color = temp.parent.color
                temp.parent.color = BLACK
                w.left.color = BLACK
                rbtree_right_rotate(tree, sentinel, temp.parent)
                temp = tree.root
            end
        end
    end

    temp.color = BLACK
end

return {
	new = rbtree_new,
}
